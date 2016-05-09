#include "utils.hpp"
#include <boost/uuid/sha1.hpp>
#include <vector>
using namespace boost::uuids::detail;

#ifdef _WIN32
#include "winsock2.h"
#else
#include <arpa/inet.h>
#endif


sha1_hash sha1_fun(const byte* buf, int len)
{
	sha1 hash;
	unsigned int digest[5];
	hash.process_bytes(buf, len);
	hash.get_digest(digest);
	for (short i = 0; i < 5; i++) {
		digest[i] = htonl(digest[i]);
	}
	sha1_hash ret(reinterpret_cast<byte*>(digest));
	return ret;
}