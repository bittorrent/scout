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
#include "scout.hpp"
#include "DhtImpl.h"
#include <sodium/crypto_sign.h>
#include <sodium/crypto_scalarmult.h>

namespace scout
{

namespace
{
	// context for the DHT put callbacks: 
	struct dht_put_context {

		entry_updated entry_cb;
		finalize_entries finalize_cb;
		sync_finished finished_cb;
		secret_key secret;
		std::map<uint32_t, entry> entries_map;

		dht_put_context(std::vector<entry> const& entries
			, secret_key_span key
			, entry_updated e_cb
			, finalize_entries f_cb
			, sync_finished s_cb)
			: entry_cb(std::move(e_cb))
			, finalize_cb(std::move(f_cb))
			, finished_cb(std::move(s_cb))
		{
			std::copy(key.begin(), key.end(), secret.data());
			// build a map of entries, indexed by id, based on the vector of entries:
			for (entry const& e : entries)
				entries_map.emplace(e.id(), e);
		}
	};
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

std::pair<secret_key, public_key> generate_keypair()
{
	secret_key sk;
	public_key pk;
	crypto_box_keypair((unsigned char*)pk.data()
		, (unsigned char*)sk.data());
	return{ sk, pk };
}

secret_key key_exchange(csecret_key_span sk, cpublic_key_span pk)
{
	secret_key ret;
	crypto_scalarmult((unsigned char*)ret.data()
		, (unsigned char const*)sk.data()
		, (unsigned char const*)pk.data());
	return ret;
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
		delete (put_finished *)ctx;
	};

	// call immutablePut:
	dht.ImmutablePut((const byte *)blob.data(), blob.size(), put_completed_callback, (void*)callback_ctx);
}

void get(IDht& dht, chash_span address, item_received received_cb)
{
	// allocate a new put_finished callback which we'll pass in as context 
	// for the C-style put_completed_callback:
	item_received *callback_ctx = new item_received(std::move(received_cb));

	// define a lambda function for handling the get callback:
	auto get_callback = [](void *ctx, std::vector<char> const& buffer) {
		hash next_hash;
		// create a span of gsl::byte from the dht buffer:
		gsl::span<gsl::byte const> buffer_span = gsl::as_bytes(gsl::as_span(buffer.data(), buffer.size()));

		// skip the bencode length prefix
		while (buffer_span.size() > 0) {
			gsl::byte first = *buffer_span.begin();
			buffer_span = buffer_span.subspan(1);
			if (char(first) == ':') break;
		}

		// extract the message contents and the next hash from the DHT blob:
		auto msg_contents = message_dht_blob_read(buffer_span, next_hash);
		// cast the context pointer to an item_received callback and call it:
		item_received callback = *((item_received *)ctx);
		callback(std::move(msg_contents), next_hash);
		delete (item_received *)ctx;
	};

	sha1_hash target_hash((const byte *)address.data());

	dht.ImmutableGet(target_hash, get_callback, (void*)callback_ctx);
}

int put_callback(void* ctx, std::vector<char>& buffer, int64& seq, SockAddr src)
{
	dht_put_context* context = static_cast<dht_put_context*>(ctx);

	if (!context) {
		// TODO: log an error
		buffer.assign({ '0', ':' });
		return 1;
	}

	std::vector<entry> entries;
	// populate the vector with entries we saved in the context's map:
	for (auto &map_entry : context->entries_map)
		entries.push_back(map_entry.second);

	// call the finalize callback to let the client perform
	// a final update on the vector of entries:
	context->finalize_cb(entries);

	// serialize the entries:
	std::vector<char> final_buffer(1000);
	auto residue = serialize(entries, gsl::as_writeable_bytes(gsl::as_span(final_buffer)));
	final_buffer.resize(final_buffer.size() - residue.size());

	// encrypt the buffer:
	buffer = encrypt_buffer(final_buffer, context->secret);
	// add the length prefix:
	std::string prefix = std::to_string(buffer.size()) + ":";
	buffer.insert(buffer.begin(), prefix.begin(), prefix.end());
	return 0;
}

int put_data_callback(void* ctx, std::vector<char> const& buffer, int64 seq, SockAddr src)
{
	dht_put_context* context = static_cast<dht_put_context*>(ctx);

	if (!context) {
		// TODO: log an error
		return 1;
	}

	// skip the length prefix
	int skip = 0;
	while (skip < int(buffer.size())) {
		++skip;
		if (buffer[skip - 1] == ':') break;
	}
	std::vector<char> buffer2(buffer.begin() + skip, buffer.end());

	// decrypt the buffer:
	std::vector<char> plaintext = decrypt_buffer(buffer2, context->secret);

	if (plaintext.empty() && !buffer2.empty()) {
		// TODO: log an error
		return 0;
	}

	// parse the blob into a vector of entries:
	std::vector<entry> blob_entries;
	parse(gsl::as_bytes(gsl::as_span(plaintext)), blob_entries);
	
	auto &e_map = context->entries_map;
	// check if there are new entries or if the seq number has changed:
	for (entry &e : blob_entries) 
	{
		// try inserting the current entry in the map:
		auto ret = e_map.insert(std::pair<uint32_t, entry>(e.id(), e));

		if (ret.second == true)
		{	// the element was inserted (it wasn't in the map before).
			// call the entry_updated callback to notify the client of the new entry:
			context->entry_cb(e);
		}
		else if (e.seq() > ret.first->second.seq())
		{	// this entry already exists in the map, but its sequence number is higher.
			// notify the client of the updated entry:
			context->entry_cb(e);
			// and update the existing entry in the map:
			ret.first->second.update_seq(e.seq());
			ret.first->second.update_contents(e.value());
		}
	}

	return 0;
}

void synchronize(IDht& dht, secret_key_span shared_key, std::vector<entry> const& entries
	, entry_updated entry_cb, finalize_entries finalize_cb, sync_finished finished_cb)
{
	std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> target_public;
	std::array<unsigned char, crypto_sign_SECRETKEYBYTES> target_private;
	// generate a key pair from the shared secret which will be used
	// as the target keypair for the DHT put call:
	crypto_sign_seed_keypair(target_public.data(), target_private.data(), (const unsigned char*) shared_key.data());

	// store context info for the callbacks:
	dht_put_context *put_context = new dht_put_context(entries, shared_key, entry_cb, finalize_cb, finished_cb);	

	// create a lambda function for the final callback:
	auto put_completed_callback = [](void *ctx) {
		// extract the dht put context:
		dht_put_context *context = (dht_put_context *)ctx;
		// call the finished callback:
		context->finished_cb();
		delete context;
	};

	// DHT mutable put call:
	dht.Put(target_public.data(), target_private.data(), put_callback, put_completed_callback, put_data_callback, put_context);
}

} // namespace scout
