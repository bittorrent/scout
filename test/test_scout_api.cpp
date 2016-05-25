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