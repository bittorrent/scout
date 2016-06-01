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

#include "utils.hpp"
#include <boost/uuid/sha1.hpp>
#include <vector>
#include <memory>
#include <cassert>
#include <sodium/crypto_secretbox.h>
#include <sodium/randombytes.h>

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
std::vector<gsl::byte> message_dht_blob_read(gsl::span<gsl::byte const> dht_blob, hash& next_msg_hash)
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
	dht_blob = extract(gsl::as_span(msg_contents), dht_blob.subspan(header.msg_offset, header.msg_length));

	return msg_contents;
}

void log_debug(char const* fmt, ...)
{
	va_list vl;
	va_start(vl, fmt);
	vfprintf(stderr, fmt, vl);
	va_end(vl);
	fprintf(stderr, "\n");
}

void log_error(char const* fmt, ...)
{
	va_list vl;
	va_start(vl, fmt);
	vfprintf(stderr, fmt, vl);
	va_end(vl);
	fprintf(stderr, "\n");
}

std::vector<char> decrypt_buffer(std::vector<char> buffer, secret_key_span sk)
{
	std::vector<char> plaintext;

	if (buffer.size() <= crypto_secretbox_NONCEBYTES + crypto_secretbox_BOXZEROBYTES)
		return plaintext;

	// pull out the nonce bytes from the start of the buffer
	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	std::memcpy(nonce, &buffer[0], crypto_secretbox_NONCEBYTES);
	buffer.erase(buffer.begin(), buffer.begin() + crypto_secretbox_NONCEBYTES);

	// prepend the zero-padding space needed by
	// crypto_box_open()
	buffer.resize(buffer.size() + crypto_secretbox_BOXZEROBYTES);
	std::memmove(&buffer[crypto_secretbox_BOXZEROBYTES], &buffer[0]
		, buffer.size() - crypto_secretbox_BOXZEROBYTES);
	std::memset(&buffer[0], 0, crypto_secretbox_BOXZEROBYTES);
	plaintext.resize(buffer.size());

	// crypto_secretbox_open(m,c,mlen,n,sk);
	// m: plain text message [out]
	// c: cipher text [in]
	// mlen: length of message [in]
	// n: nonce bytes [in]
	// sk: secret key [in]
	int ret = crypto_secretbox_open((unsigned char*)&plaintext[0]
		, (unsigned char*)&buffer[0]
		, buffer.size()
		, nonce
		, (const unsigned char*) sk.data());

	if (ret != 0) {
		plaintext.clear();
		return plaintext;
	}

	// now, strip the leading zeroes
	plaintext.erase(plaintext.begin(), plaintext.begin() + crypto_secretbox_ZEROBYTES);
	return plaintext;
}

std::vector<char> encrypt_buffer(std::vector<char> buffer, secret_key_span sk, const unsigned char* nonce_in)
{
	// first, generate a nonce
	unsigned char nonce[crypto_secretbox_NONCEBYTES];
	if (nonce_in) {
		std::copy(nonce_in, nonce_in + crypto_secretbox_NONCEBYTES, nonce);
	}
	else {
		randombytes(nonce, crypto_secretbox_NONCEBYTES);
	}

	// then prepend the zero padding
	buffer.resize(buffer.size() + crypto_secretbox_ZEROBYTES);
	std::memmove(&buffer[crypto_secretbox_ZEROBYTES], &buffer[0]
		, buffer.size() - crypto_secretbox_ZEROBYTES);
	std::memset(&buffer[0], 0, crypto_secretbox_ZEROBYTES);

	std::vector<char> ciphertext;
	ciphertext.resize(buffer.size());

	crypto_secretbox((unsigned char*)&ciphertext[0] // destination buffer
		, (const unsigned char*)&buffer[0] // source plaintext buffer
		, buffer.size()
		, nonce // nonce bytes
		, (const unsigned char*)sk.data());

	// strip the remaining zero-padding
	ciphertext.erase(ciphertext.begin(), ciphertext.begin()
		+ crypto_secretbox_BOXZEROBYTES);

	// prepend the nonce
	ciphertext.insert(ciphertext.begin(), nonce, nonce + crypto_secretbox_NONCEBYTES);
	return ciphertext;
}
