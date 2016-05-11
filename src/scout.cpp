#include "utils.hpp"
#include "scout.hpp"
#include "DhtImpl.h"


namespace scout
{

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

void get(IDht& dht, hash_span address, item_received received_cb)
{
	// allocate a new put_finished callback which we'll pass in as context 
	// for the C-style put_completed_callback:
	item_received *callback_ctx = new item_received(std::move(received_cb));

	// define a lambda function for handling the get callback:
	auto get_callback = [](void *ctx, std::vector<char> const& buffer) {
		hash next_hash;
		// create a span of gsl::byte from the dht buffer:
		gsl::span<gsl::byte const> buffer_span = gsl::as_bytes(gsl::as_span(buffer.data(), buffer.size()));
		// extract the message contents and the next hash from the DHT blob:
		auto msg_contents = message_dht_blob_read(buffer_span, next_hash);
		// cast the context pointer to an item_received callback and call it:
		item_received callback = *((item_received *)ctx);
		callback(std::move(msg_contents), next_hash);
		delete &callback;
	};

	sha1_hash target_hash((const byte *)address.data());

	dht.ImmutableGet(target_hash, get_callback, (void*)callback_ctx);
}

} // namespace scout
