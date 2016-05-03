#include <vector>
#include <array>
#include <cstdint>
#include <functional>
#include <span.h>
#include "ut_dht/src/dht.h"

namespace scout
{

using secret_key = std::array<gsl::byte, 32>;
using secret_key_span = gsl::span<gsl::byte, 32>;
using hash = std::array<gsl::byte, 20>;
using hash_span = gsl::span<gsl::byte, 20>;

// a mutable blob of data
// each entry has an id associated with it which must be unique among the entries it is stored with
class entry
{
public:
	entry(uint32_t id) : m_seq(0), m_id(id) {}

	uint32_t id() const { return m_id; }
	std::vector<gsl::byte> const& value() const { return m_contents; }
	void assign(gsl::span<gsl::byte const> contents)
	{
		m_contents.assign(contents.begin(), contents.end());
		++m_seq;
	}

	// internal
	entry(int64_t seq, uint32_t id) : m_seq(seq), m_id(id) {}

private:
	std::vector<gsl::byte> m_contents;
	int64_t m_seq;
	uint32_t const m_id;
};

// a token is associated with each piece of immutable data stored in a list
// it should be stored alongside the data and passed along with it to put
class list_token
{
public:
	hash const& next() const { return m_next; }

	// internal
	explicit list_token(hash next) : m_next(next) {}

private:
	hash m_next;
};

// The head of a linked-list stored in the DHT. New items can only be inserted
// at the head of the list and list can only be retrieved starting at the head (LIFO).
class list_head
{
public:
	// add an item to the linked-list
	// the returned list_token should be stored with the contents and passed to put()
	list_token push_front(gsl::span<gsl::byte const> contents);

	// get the hash of the head of the list
	// this can be passed to get() to retrieve the first item in the list
	hash const& head() const { return m_head; }

private:
	hash m_head;
};

gsl::span<gsl::byte> serialize(entry const& entry, gsl::span<gsl::byte> output);
gsl::span<gsl::byte> serialize(gsl::span<entry const> entries, gsl::span<gsl::byte> output);
gsl::span<gsl::byte> serialize(list_token const& item, gsl::span<gsl::byte> output);
gsl::span<gsl::byte> serialize(list_head const& head, gsl::span<gsl::byte> output);

gsl::span<gsl::byte const> parse(gsl::span<gsl::byte const> input, entry& entry);
gsl::span<gsl::byte const> parse(gsl::span<gsl::byte const> input, std::vector<entry>& entries);
gsl::span<gsl::byte const> parse(gsl::span<gsl::byte const> input, list_token& item);
gsl::span<gsl::byte const> parse(gsl::span<gsl::byte const> input, list_head& stack);

// called when a new or updated entry is received from the DHT
using entry_updated = std::function<void(std::vector<entry>::iterator e)>;
// called just before the list of entries is stored in the DHT
using finalize_entries = std::function<void(std::vector<entry>& entries)>;
// called when storing the current entry list has completed
using sync_finished = std::function<void()>;
// called when the value associated with the hash has been received
// the DHT transaction ends after this function is called
// if no value is found an empty span will be passed
using item_received = std::function<void(list_token const& token, gsl::span<gsl::byte const> contents)>;
// called when a put has completed
using put_finished = std::function<void()>;

// synchronize a list of entries with the DHT
// this will first update the given vector with any new or updated entries from the DHT
// then store the updated list in the DHT
void synchronize(IDht& dht, secret_key_span shared_key, std::vector<entry>& entries
	, entry_updated entry_cb, finalize_entries finalize_cb, sync_finished finished_cb);

// store an immutable item in the DHT
void put(IDht& dht, list_token const& token, gsl::span<gsl::byte const> contents
	, put_finished finished_cb);

// retrieve an immutable item from the DHT
void get(IDht& dht, hash_span address, item_received received_cb);

}
