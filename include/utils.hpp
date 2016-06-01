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

#ifndef UTILS_HPP
# define UTILS_HPP

#include <scout.hpp>
#include <sha1_hash.h>
#include <boost/endian/arithmetic.hpp>
#include <sodium/crypto_box.h>
#include <sodium/randombytes.h>
#include <cstring>

namespace be = boost::endian;
using namespace scout;

struct entry_header
{
	be::big_int64_t seq;
	be::big_uint32_t id;
	std::array<gsl::byte, 2> reserved;
	uint8_t content_length;
	// offset from this field to the first byte of content
	// This is for extensibility. If we want to add more header fields
	// later on we can increase the offset and old clients will apply
	// the offset and skip the part of the header they don't understand.
	uint8_t content_offset;
};

struct entries_header
{
	uint8_t entry_count;
	uint8_t entries_offset; // offset from this field to the first entry
};

struct dht_msg_header
{
	hash next_hash;
	be::big_uint16_t msg_length;
	uint8_t msg_offset;
};

sha1_hash sha1_fun(const byte* buf, int len);

template <typename T, std::ptrdiff_t... Dimensions>
gsl::span<gsl::byte const> extract(gsl::span<T, Dimensions...> dest, gsl::span<gsl::byte const> src)
{
	static_assert(std::is_trivial<std::decay_t<T>>::value, "Target type must be a trivial type");

	if (src.size_bytes() < dest.size_bytes())
		throw std::length_error("bytes span smaller than destination");
	std::memcpy(dest.data(), src.data(), dest.size_bytes());
	return{ src.data() + dest.size_bytes(), src.size_bytes() - dest.size_bytes() };
}

template <typename T, std::ptrdiff_t... Dimensions>
gsl::span<gsl::byte> flatten(gsl::span<gsl::byte> dest, gsl::span<T const, Dimensions...> src)
{
	static_assert(std::is_trivial<std::decay_t<T>>::value, "Target type must be a trivial type");

	if (dest.size_bytes() < src.size_bytes())
		throw std::length_error("source span larger than destination");
	std::memcpy(dest.data(), src.data(), src.size_bytes());
	return{ dest.data() + src.size_bytes(), dest.size_bytes() - src.size_bytes() };
}

std::vector<gsl::byte> message_dht_blob_write(gsl::span<gsl::byte const> msg_data, chash_span next_msg_hash);
std::vector<gsl::byte> message_dht_blob_read(gsl::span<gsl::byte const> dht_blob, hash& next_msg_hash);

void log_debug(char const* fmt, ...);
void log_error(char const* fmt, ...);

// crypto helper functions:
std::vector<char> decrypt_buffer(std::vector<char> buffer, secret_key_span secret);
std::vector<char> encrypt_buffer(std::vector<char> buffer, secret_key_span secret, const unsigned char* nonce_in = nullptr);

#endif