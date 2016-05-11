#include "utils.hpp"
#include <boost/uuid/sha1.hpp>
#include <vector>
#include <memory>
#include <cassert>
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


// format the dht blob for a message in the linked list (message data and hash of the next message):
std::vector<gsl::byte> message_dht_blob_write(gsl::span<gsl::byte const> msg_data, chash_span next_msg_hash)
{
	std::vector<gsl::byte> blob(msg_data.size() + sizeof(dht_msg_header));

	gsl::span<gsl::byte> output = gsl::as_span(blob);

	// format the dht msg header:
	dht_msg_header header;
	std::copy(next_msg_hash.begin(), next_msg_hash.end(), header.next_hash.data());
	header.msg_length = msg_data.size();
	header.msg_offset = 0;
	// serialize the header:
	output = flatten(output, gsl::span<dht_msg_header const, 1>(header));
	// serialize the message:
	output = flatten(output, msg_data);

	return blob;
}

// this function takes in the dht buffer, parses it and returns a vector representing the message contents
// and a hash pointing to the next message in the linked list:
std::vector<gsl::byte> message_dht_blob_read(gsl::span<gsl::byte const> dht_blob, hash_span next_msg_hash)
{
	// if the buffer is empty, return an empty vector:
	if (dht_blob.size() == 0)
		return{};

	// extract the header:
	dht_msg_header header;
	dht_blob = extract(gsl::span<dht_msg_header, 1>(header), dht_blob);
	// get the next hash from the extracted header:
	std::copy(header.next_hash.begin(), header.next_hash.end(), next_msg_hash.data());
	// return an empty vector if the buffer isn't long enough for the message length:
	if (dht_blob.size() < header.msg_offset + header.msg_length)
		return{};

	// prepare a vector to receive the message contents:
	std::vector<gsl::byte> msg_contents(header.msg_length);
	// apply the offset (if any) and extract the actual message contents:
	dht_blob = extract(gsl::as_span(msg_contents), dht_blob.subspan(header.msg_offset, header.msg_offset + header.msg_length));

	return msg_contents;
}