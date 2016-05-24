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

