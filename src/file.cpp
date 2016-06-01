/*
Copyright 2016 BitTorrent Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "file.hpp"
#include <fcntl.h>
#include <thread>
#include <sys/stat.h>
#include <boost/system/system_error.hpp>
#include "utils.hpp" // for log_error

#if defined __APPLE__
#include "TargetConditionals.h"
#endif

#if TARGET_OS_IPHONE 
#include "file_cocoa.h"	// for printing iOS file attributes
#endif

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#endif


#ifndef _WIN32
std::mutex file::m_mutex;
std::unordered_set<ino_t> file::m_locked_inodes;
#endif

#ifdef _WIN32
#define posix_close _close
#define posix_read _read
#define posix_write _write
#define posix_fstat _fstat
#define posix_lseek _lseek
#define posix_fsync _commit
#define stat _stat
#else
#define posix_close close
#define posix_read read
#define posix_write write
#define posix_fstat fstat
#define posix_lseek lseek
#define posix_fsync fsync
#endif

file::~file()
{
	close();
}

#ifndef _WIN32
void file::unlock_inode(ino_t ino)
{
	if (ino) {
		std::lock_guard<std::mutex> l(m_mutex);
		m_locked_inodes.erase(ino);
	}
}
#endif

void file::close()
{
#ifndef _WIN32
	if (m_inode_locked) {
		unlock_inode(m_inode_locked);
		m_inode_locked = 0;
	}
#endif

	if (m_fd == -1)
		return;

	::posix_close(m_fd);
	m_fd = -1;
}

file::file(char const* filename, int flags)
	: m_fd(-1)
#ifndef _WIN32
	, m_inode_locked(0)
#endif
{
	open(filename, flags);
}

void file::open(char const* filename, int flags)
{
#ifdef _WIN32

	HANDLE h = INVALID_HANDLE_VALUE;

	DWORD access = GENERIC_READ;
	if (flags & read_write)
		access |= GENERIC_WRITE;
	if (flags & append)
		access = FILE_APPEND_DATA;

	DWORD share_mode = FILE_SHARE_WRITE | FILE_SHARE_READ;

	// share mode 0 means nobody else is allowed to open
	// this file while we have it open
	if (flags & exclusive)
		share_mode = 0;

	DWORD disposition = OPEN_EXISTING;
	if (flags & create)
		disposition = OPEN_ALWAYS;

	h = CreateFile(filename, access, share_mode, nullptr, disposition
		, FILE_ATTRIBUTE_NORMAL, nullptr);

	// if we want exclusive access and we fail, retry one second later
	int retry = 0;
	while (h == INVALID_HANDLE_VALUE
		&& (flags & exclusive)
		&& GetLastError() == ERROR_SHARING_VIOLATION
		&& retry < 5) {

		std::this_thread::sleep_for(std::chrono::seconds(1));

		// retry
		++retry;
		h = CreateFile(filename, access, share_mode, nullptr, disposition
			, FILE_ATTRIBUTE_NORMAL, nullptr);
	}

	if (h == INVALID_HANDLE_VALUE) {
		throw boost::system::system_error(error_code(GetLastError()
			, boost::system::system_category()));
	}

	close();
	m_fd = _open_osfhandle((intptr_t)h, 0);

#else


	int oflags = 0;

	// you're not allowed to lock a file that's opened in read-only mode
	if ((flags & read_write) || (flags & exclusive))
		oflags = O_RDWR;
	else
		oflags = O_RDONLY;

	if (flags & create)
		oflags |= O_CREAT;

	if (flags & exclusive)
		oflags |= O_EXCL;

	if (flags & append)
		oflags |= O_APPEND;

	int fd = ::open(filename, oflags, S_IRUSR | S_IWUSR);

	if (fd < 0 && (flags & exclusive)) {
		fd = ::open(filename, oflags & ~(O_EXCL | O_CREAT)
			, S_IRUSR | S_IWUSR);
	}

	if (fd < 0) {
		throw boost::system::system_error(error_code(errno
			, boost::system::system_category()));
	}
    
#if TARGET_OS_IPHONE
    set_file_attributes(std::string(filename));
#endif

	// if we fail, we need to close fd
	auto guard = make_guard([=] { ::close(fd); });

	ino_t locked_inode = 0;
	auto inode_guard = make_guard([&] { unlock_inode(locked_inode); });

	if (flags & exclusive) {

		// file locks in posix are per-process, not per file descriptor.
		// two separate file descriptors can acquire the lock to the
		// same file, as long as they are both within the same process.
		// we want per-handle semantics in our locking, so we introduce a
		// concept of locking a file within a process. This is simply to
		// synchronize the handles within the same process, such that only
		// one handle then moves on to attempting to acquire the actual
		// file lock.

		// first we need to find the inode number for this file. This is the
		// unique identifier for the file we want to lock.
		struct stat st;
		int ret = fstat(fd, &st);
		if (ret != 0) {
			log_error("failed to stat file \"%s\" [%d]: (%d) %s\n"
				, filename, fd, errno, strerror(errno));
			::close(fd);
			throw boost::system::system_error(error_code(errno
				, boost::system::system_category()));
		}

		ino_t ino = st.st_ino;
		// there is an assumption that inode no. cannot be 0
		assert(ino != 0);

		// Attempt to lock the file, retry for a few seconds
		int retry = 0;

		{
			// now that we know the inode number, try to acquire the process-wide
			// lock for this file
			std::lock_guard<std::mutex> l(m_mutex);
			while (m_locked_inodes.count(ino) > 0) {
				m_mutex.unlock();
				++retry;

				// if we fail to grab the lock for 5 seconds, give up
				if (retry >= 5) {
					::close(fd);
					throw boost::system::system_error(error_code(EBADF
						, boost::system::system_category()));
				}

				std::this_thread::sleep_for(std::chrono::seconds(1));
				m_mutex.lock();
			}

			// we have the lock of this inode now
			locked_inode = ino;
			m_locked_inodes.insert(ino);
		}

		struct flock lock;

		lock.l_start = 0;
		lock.l_len = 0;
		lock.l_type = F_WRLCK;
		lock.l_whence = SEEK_SET;
		lock.l_pid = getpid();

		int locked = fcntl(fd, F_SETLK, &lock);
		// fcntl returns -1 upon failure
		while (locked == -1 && retry < 5)
		{
			retry++;
			std::this_thread::sleep_for(std::chrono::seconds(1));
			locked = fcntl(fd, F_SETLK, &lock);
		}
		if (locked == -1) {
			log_error("failed to lock file \"%s\" [%d]: (%d) %s\n"
				, filename, fd, errno, strerror(errno));
			::close(fd);
			throw boost::system::system_error(error_code(errno
				, boost::system::system_category()));
		}
	}

	close();

	inode_guard.disarm();
	m_inode_locked = locked_inode;

	// ignore errors here. This is just to make sure old existing files have
	// appropriate protection bits
	fchmod(fd, S_IRUSR | S_IWUSR);

	guard.disarm();
	m_fd = fd;
#endif
}

void file::truncate(int size)
{
#ifdef _WIN32
	HANDLE h = (HANDLE)_get_osfhandle(m_fd);
	FILE_END_OF_FILE_INFO eofi;
	eofi.EndOfFile.QuadPart = size;
	BOOL ret = SetFileInformationByHandle(h, FileEndOfFileInfo
		, &eofi, sizeof(eofi));

	if (ret == FALSE)
		throw boost::system::system_error(error_code(GetLastError()
			, boost::system::system_category()));
#else
	int ret = ftruncate(m_fd, size);
	if (ret != 0)
		throw boost::system::system_error(error_code(errno
			, boost::system::generic_category()));
#endif
}

void file::seek(int pos)
{
	int ret = ::posix_lseek(m_fd, pos, SEEK_SET);
	if (ret < 0)
		throw boost::system::system_error(error_code(errno
			, boost::system::system_category()));
}

int file::read(char* buf, int len)
{
	if (len == 0) return 0;
	int ret = 0;
	do {
		int r = ::posix_read(m_fd, buf, len);

		// read() returning 0 means End Of File.
		// in that case we need to leave the loop
		if (r < 0) {
			throw boost::system::system_error(error_code(errno
				, boost::system::system_category()));
		}
		if (r == 0) break;

		ret += r;
		len -= r;
	} while (len > 0);
	return ret;
}

int file::write(char const* buf, int len)
{
	if (len == 0) return 0;
	int length = len;
	do {
		int w = ::posix_write(m_fd, buf, len);

		// if we fail to write any bytes, but without getting
		// an error, we risk ending up in an infinite loop,
		// and we should leave.
		if (w <= 0) {
			throw boost::system::system_error(error_code(errno
				, boost::system::system_category()));
		}

		len -= w;
	} while (len > 0);
	return length;
}

int file::flush()
{
	return posix_fsync(m_fd);
}

int64_t file::size()
{
	// Figure out the size of the file, so that we can read entire file
	struct stat st;
	int ret = ::posix_fstat(m_fd, &st);

	// 0 means success
	if (ret < 0) {
		throw boost::system::system_error(error_code(errno
			, boost::system::system_category()));
		return 0;
	}

	return st.st_size;
}

