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

#ifndef FILE_HPP
#define FILE_HPP

#include <boost/system/error_code.hpp>
#include <mutex>
#include <unordered_set>

using boost::system::error_code;

struct file
{

	file()
		: m_fd(-1)
#ifndef _WIN32
		, m_inode_locked(0)
#endif
	{}
	~file();

	file(file const&) = delete;
	file(char const* filename, int flags);
	file& operator=(file const&) = delete;

	enum flags_t { read_only = 0, read_write = 1
		, create = 2, exclusive = 4, append = 8 };
	void open(char const* filename, int flags);
	void seek(int pos);

	void close();
	void truncate(int size);

	int read(char* buf, int len);
	int write(char const* buf, int len);

	int flush();

	int64_t size();

	bool is_open() const { return m_fd != 0; }

	int native_handle() { return m_fd; }

private:

	int m_fd;

#ifndef _WIN32
	// this is used to implement a per file descriptor lock of the underlying
	// inode number. This is to extend the posix file locking to have the
	// same semantics as on windows, where a file handle owns file locks,
	// not a process.
	static std::mutex m_mutex;
	static std::unordered_set<ino_t> m_locked_inodes;

	// if this handle holds a lock on its inode, this is set to a non-zero value
	ino_t m_inode_locked;
	void unlock_inode(ino_t ino);
#endif

};
#endif

