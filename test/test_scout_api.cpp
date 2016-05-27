#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include <scout.hpp>
#include <utils.hpp>
#include "fake_dht.h"

using namespace scout;
using b = gsl::byte;

TEST(scout_api, put)
{
	FakeDhtImpl fake_dht = FakeDhtImpl();
	init(fake_dht);

	std::string test_msg = "test message";
	auto test_msg_span = gsl::as_bytes(gsl::as_span(test_msg.c_str(), test_msg.size()));

	// create a message list:
	list_head msg_list;
	// add a message to the list:
	list_token msg_token = msg_list.push_front(test_msg_span);

	bool finished_cb_called = false;

	put_finished finished_cb = [&] {
		finished_cb_called = true;
		// check the blob that's been written to the DHT:
		auto dht_blob_span = gsl::as_bytes(gsl::as_span(fake_dht.immutableData));
		hash parsed_hash;
		// parse the blob and extract the hash and message:
		auto parsed_msg = message_dht_blob_read(dht_blob_span, parsed_hash);
		// check that the parsed hash matches the message token's next hash:
		EXPECT_EQ(msg_token.next(), parsed_hash);
		// check that the parsed message matches:
		EXPECT_TRUE(std::equal(test_msg_span.begin(), test_msg_span.end(), parsed_msg.begin()));
	};

	put(fake_dht, msg_token, test_msg_span, finished_cb);

	// check that ImmutablePut got called:
	EXPECT_TRUE(fake_dht.immutableData.size() > 0);
	// check that the finished callback got called:
	EXPECT_TRUE(finished_cb_called);
}

TEST(scout_api, get)
{
	FakeDhtImpl fake_dht = FakeDhtImpl();
	init(fake_dht);

	std::string test_msg = "test message";
	auto test_msg_span = gsl::as_bytes(gsl::as_span(test_msg.c_str(), test_msg.size()));

	hash const test_hash = { b(0), b(1), b(2), b(3), b(4), b(5), b(6), b(7), b(8), b(9),
		b(10), b(11), b(12), b(13), b(14), b(15), b(16), b(17), b(18), b(19) };

	chash_span test_hash_span = gsl::as_span(test_hash);

	// form a dht blob from the message and hash and save it in the fake DHT:
	auto dht_blob = message_dht_blob_write(test_msg_span, test_hash_span);
	fake_dht.immutableData.assign((char*)dht_blob.data(), (char*)dht_blob.data() + dht_blob.size());

	// create a message list:
	list_head msg_list;
	// add a message to the list:
	list_token msg_token = msg_list.push_front(test_msg_span);

	bool received_cb_called = false;

	item_received received_cb = [&](std::vector<gsl::byte> contents, hash const& next_hash) {
		received_cb_called = true;
		// check that the received hash matches:
		EXPECT_EQ(next_hash, test_hash);
		// check that the received message matches:
		EXPECT_TRUE(std::equal(test_msg_span.begin(), test_msg_span.end(), contents.begin()));
	};

	hash target_hash;
	get(fake_dht, target_hash, received_cb);
	// check that the received callback was called:
	EXPECT_TRUE(received_cb_called);
}

TEST(scout_api, synchronize)
{
	// initialize fake dht:
	FakeDhtImpl fake_dht = FakeDhtImpl();
	init(fake_dht);

	std::array<char, 10> const test_content[]
	{ { 0, 1, 2, 3, 4, 5, 6, 7 , 8, 9 },
	{ 10, 11, 12, 13, 14, 15, 16, 17 , 18, 19 },
	{ 20, 21, 22, 23, 24, 25, 26, 27 , 28, 29 } };

	// create a vector of entries for testing:
	std::vector<entry> entries;

	int num_entries = 3;

	for (int i = 0; i < num_entries; ++i)
	{
		entries.emplace_back(i);
		entries.back().assign(gsl::as_span(test_content[i]));
	}

	// generate Alice's key pair (our keypair):
	std::pair<secret_key, public_key> aliceKeyPair = generate_keypair();
	// generate Bob's key pair (remote contact keypair):
	std::pair<secret_key, public_key> bobKeyPair = generate_keypair();
	// perform a DH exchange between our private key and the remote's public:
	secret_key shared_key = key_exchange(aliceKeyPair.first, bobKeyPair.second);

	bool entry_cb_called = false;
	bool finalize_cb_called = false;
	bool finished_cb_called = false;

	// create some fake modified entries from the initial vector of entries:
	std::vector<entry> entries_modified = entries;
	// add a new entry:
	entries_modified.emplace_back(num_entries + 1);
	char new_entry_content[] = { 30, 31, 32, 33, 34, 35, 36, 37, 38, 39 };
	entries_modified.back().assign(gsl::as_span(new_entry_content));
	// modify one of the existing entries:
	entries_modified[0].update_seq(entries_modified[0].seq() + 1);
	std::vector<gsl::byte> modified_entry_content = { b(6), b(6), b(6) };
	entries_modified[0].update_contents(modified_entry_content);
	// format the entries into a dht blob and feed it into the fake dht in order 
	// to simulate updated entries for the put data callback:
	std::vector<char> buffer(1000);
	serialize(entries_modified, gsl::as_writeable_bytes(gsl::as_span(buffer)));
	buffer = encrypt_buffer(buffer, shared_key);
	std::string prefix = std::to_string(buffer.size()) + ":";
	buffer.insert(buffer.begin(), prefix.begin(), prefix.end());
	fake_dht.putDataCallbackBuffer = buffer;

	entry_updated entry_cb = [&](entry const& e) {
		entry_cb_called = true;
		// check that this callback is being called for the modified entries:
		if (e.seq() == 1) 
		{	// this is the newly added entry...
			// check that the new entry matches:
			EXPECT_TRUE(std::equal(e.value().begin(), e.value().end(), entries_modified.back().value().begin()));
		}
		else 
		{	// this is the updated entry:
			EXPECT_TRUE(e.seq() == 2);
			// check that the updated entry matches:
			EXPECT_TRUE(std::equal(e.value().begin(), e.value().end(), modified_entry_content.begin()));
		}
	};

	finalize_entries finalize_cb = [&](std::vector<entry>& final_entries) {
		finalize_cb_called = true;
		// check that the number of entries match:
		EXPECT_TRUE(final_entries.size() == entries_modified.size());
		// check that all the entries match:
		int i = 0;
		for (auto const &e : final_entries)
		{
			EXPECT_TRUE(e == entries_modified[i]);
			i++;
		}
	};

	sync_finished finished_cb = [&] {
		finished_cb_called = true;
	};

	synchronize(fake_dht, shared_key, entries, entry_cb, finalize_cb, finished_cb);

	// check that the callbacks have been called:
	EXPECT_TRUE(entry_cb_called);
	EXPECT_TRUE(finalize_cb_called);
	EXPECT_TRUE(finished_cb_called);
}