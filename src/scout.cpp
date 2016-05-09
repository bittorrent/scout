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
	input = extract(gsl::span<entry_header, 1>(header), input);
	input = input.subspan(header.content_offset);
	entry e(header.seq, header.id, { input.begin(), input.begin() + header.content_length });
	input = input.subspan(header.content_length);
	return{ std::move(e), input };
}

gsl::span<gsl::byte> entry::serialize(gsl::span<gsl::byte> output) const
{
	entry_header header;
	header.id = id();
	header.seq = m_seq;
	header.reserved.fill(gsl::byte(0));
	assert(value().size() <= (std::numeric_limits<uint8_t>::max)());
	header.content_length = uint8_t(value().size());
	header.content_offset = 0;

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
	header.entry_count = entries.size();
	header.entries_offset = 0;

	output = flatten(output, gsl::span<entries_header const, 1>(header));
	for (entry const& e : entries)
		output = e.serialize(output);
	return output;
}

gsl::span<gsl::byte const> parse(gsl::span<gsl::byte const> input, std::vector<entry>& entries)
{
	entries_header header;
	input = extract(gsl::span<entries_header, 1>(header), input);
	input = input.subspan(header.entries_offset);

	for (int i = 0; i < header.entry_count; ++i)
	{
		auto entry = entry::parse(input);
		input = entry.second;
		entries.emplace_back(std::move(entry.first));
	}

	return input;
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
	output = flatten(blob, gsl::span<dht_msg_header const, 1>(header));
	// serialize the message:
	output = flatten(blob, msg_data);

	return blob;
}


list_token list_head::push_front(gsl::span<gsl::byte const> contents)
{
	// create a new list token which hash points to the old head:
	list_token *token = new list_token(m_head);

	// build the dht blob for the offline msg with the current head as the next hash:
	std::vector<gsl::byte> blob = message_dht_blob_write(contents, m_head);

	// add the size prefix before hashing the blob
	// (DhtImpl::ImmutablePut does that before hashing the blob):
	std::string prefix = std::to_string(blob.size()) + ":";
	gsl::byte * prefix_b = (gsl::byte *) prefix.c_str();
	blob.insert(blob.begin(), prefix_b, prefix_b + prefix.size());

	// hash the blob:
	sha1_hash new_hash = sha1_fun((const byte*)blob.data(), blob.size());

	// update the head of the linked list with the new hash:
	std::memcpy(m_head.data(), new_hash.value, m_head.size());

	return *token;
}


void put(IDht& dht, list_token const& token, gsl::span<gsl::byte const> contents, put_finished finished_cb)
{
	// build the dht blob for the offline message:
	std::vector<gsl::byte> blob = message_dht_blob_write(contents, token.next());

	// allocate a new put_finished callback which we'll pass in as context 
	// for the C-style put_completed_callback:
	put_finished *callback_ctx = new put_finished(std::move(finished_cb));

	auto put_completed_callback = [](void *ctx) {
		// cast the context pointer to a put_finished callback and call it:
		put_finished callback = *((put_finished *)ctx);
		callback();
		delete &callback;
	};

	// call immutablePut:
	dht.ImmutablePut((const byte *)blob.data(), blob.size(), put_completed_callback, (void*)callback_ctx);
}

} // namespace scout
