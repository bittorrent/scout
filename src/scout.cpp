#include "scout.hpp"
#include <boost/endian/arithmetic.hpp>
#include <memory>
#include <cassert>
#include "DhtImpl.h"
#include "utils.hpp"

namespace be = boost::endian;

namespace scout
{

namespace
{
	template <typename T, std::ptrdiff_t... Dimensions>
	gsl::span<gsl::byte const> extract(gsl::span<T, Dimensions...> dest, gsl::span<gsl::byte const> src)
	{
		static_assert(std::is_trivial<std::decay_t<T>>::value, "Target type must be a trivial type");

		if (src.size_bytes() < dest.size_bytes())
			throw std::length_error("bytes span smaller than destination");
		std::memcpy(dest.data(), src.data(), dest.size_bytes());
		return { src.data() + dest.size_bytes(), src.size_bytes() - dest.size_bytes() };
	}

	template <typename T, std::ptrdiff_t... Dimensions>
	gsl::span<gsl::byte> flatten(gsl::span<gsl::byte> dest, gsl::span<T const, Dimensions...> src)
	{
		static_assert(std::is_trivial<std::decay_t<T>>::value, "Target type must be a trivial type");

		if (dest.size_bytes() < src.size_bytes())
			throw std::length_error("source span larger than destination");
		std::memcpy(dest.data(), src.data(), src.size_bytes());
		return { dest.data() + src.size_bytes(), dest.size_bytes() - src.size_bytes() };
	}

	struct entry_header
	{
		uint8_t header_size;
		be::big_int64_t seq;
		be::big_uint32_t id;
		uint8_t content_length;
	};

	struct entries_header
	{
		uint8_t header_size;
		uint8_t entry_count;
	};
}

// do any global initialization for the scout library here:
void init(IDht &dht)
{
	// set the DHT callback:
	dht.SetSHACallback(&sha1_fun);
}

std::pair<entry, gsl::span<gsl::byte const>> entry::parse(gsl::span<gsl::byte const> input)
{
	entry_header header;
	extract(gsl::span<entry_header, 1>(header), input);
	if (header.header_size < sizeof(entry_header))
		throw std::invalid_argument("header size too small");
	input = input.subspan(header.header_size);
	entry e(header.seq, header.id, { input.begin(), input.begin() + header.content_length });
	input = input.subspan(header.content_length);
	return{ std::move(e), input };
}

gsl::span<gsl::byte> entry::serialize(gsl::span<gsl::byte> output) const
{
	entry_header header;
	header.header_size = sizeof(entry_header);
	header.id = id();
	header.seq = m_seq;
	assert(value().size() <= (std::numeric_limits<uint8_t>::max)());
	header.content_length = uint8_t(value().size());

	output = flatten(output, gsl::span<entry_header const, 1>(header));
	output = flatten(output, gsl::as_span(value()));
	return output;
}

gsl::span<gsl::byte> list_token::serialize(gsl::span<gsl::byte> output) const
{
	output = flatten(output, gsl::as_span(next()));
	return output;
}

list_token list_token::parse(gsl::span<gsl::byte const> input)
{
	hash h;
	input = extract(gsl::as_span(h), input);
	return{ h };
}

gsl::span<gsl::byte> list_head::serialize(gsl::span<gsl::byte> output) const
{
	output = flatten(output, gsl::as_span(head()));
	return output;
}

list_head list_head::parse(gsl::span<gsl::byte const> input)
{
	hash h;
	input = extract(gsl::as_span(h), input);
	return{ h };
}

gsl::span<gsl::byte> serialize(gsl::span<entry const> entries, gsl::span<gsl::byte> output)
{
	entries_header header;
	header.header_size = sizeof(entries_header);
	header.entry_count = entries.size();

	output = flatten(output, gsl::span<entries_header const, 1>(header));
	for (entry const& e : entries)
		output = e.serialize(output);
	return output;
}

gsl::span<gsl::byte const> parse(gsl::span<gsl::byte const> input, std::vector<entry>& entries)
{
	entries_header header;
	extract(gsl::span<entries_header, 1>(header), input);
	if (header.header_size < sizeof(entries_header))
		throw std::invalid_argument("header size too small");
	input = input.subspan(header.header_size);

	for (int i = 0; i < header.entry_count; ++i)
	{
		auto entry = entry::parse(input);
		input = entry.second;
		entries.emplace_back(std::move(entry.first));
	}

	return input;
}

// format the dht blob for an offline message (msg data + hash of next dht blob in the list):
std::vector<byte> message_dht_blob_write(gsl::span<gsl::byte const> contents, gsl::span<gsl::byte const> prev_msg_hash)
{
	std::vector<byte> blob(contents.size() + 300);
	smart_buffer sb((unsigned char*)blob.data(), blob.size());
	sb("d");
	sb("1:m%d:", contents.size())(contents.size(), (byte const*)contents.data());
	sb("1:n20:")(20, (byte const *)prev_msg_hash.data());
	sb("e");

	blob.resize(size_t(sb.length()));
	return blob;
}

list_token list_head::push_front(gsl::span<gsl::byte const> contents)
{
	// create a new list token which hash points to the old head:
	list_token *token = new list_token(m_head);

	// build the dht blob for the offline msg with the current head as the next hash:
	std::vector<byte> blob = message_dht_blob_write(contents, m_head);
	// add the size prefix before hashing the blob
	// (DhtImpl::ImmutablePut does that before hashing the blob):
	std::string prefix = std::to_string(blob.size()) + ":";
	blob.insert(blob.begin(), prefix.begin(), prefix.end());
	// hash the blob:
	sha1_hash new_hash = sha1_fun(blob.data(), blob.size());

	// update the head of the linked list with the new hash:
	std::memcpy(m_head.data(), new_hash.value, m_head.size());

	return *token;
}


void put(IDht& dht, list_token const& token, gsl::span<gsl::byte const> contents, put_finished finished_cb)
{
	// build the dht blob for the offline message:
	std::vector<byte> blob = message_dht_blob_write(contents, token.next());

	// allocate a new put_finished callback which we'll pass in as context 
	// for the C-style put_completed_callback:
	put_finished *callback_ctx = new put_finished(std::move(finished_cb));

	auto put_completed_callback = [](void *ctx) {
		// cast the context pointer to a put_finished callback and call it:
		put_finished callback = *((put_finished *)ctx);
		callback();
		delete ctx;
	};

	// call immutablePut:
	dht.ImmutablePut(blob.data(), blob.size(), put_completed_callback, (void*)callback_ctx);
}

} // namespace scout
