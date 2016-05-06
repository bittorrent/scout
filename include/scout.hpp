#include <vector>
#include <array>
#include <cstdint>
#include <functional>
#include <span.h>
#include <dht.h>

namespace scout
{

using secret_key = std::array<gsl::byte, 32>;
using secret_key_span = gsl::span<gsl::byte, 32>;
using csecret_key_span = gsl::span<gsl::byte const, 32>;
using hash = std::array<gsl::byte, 20>;
using hash_span = gsl::span<gsl::byte, 20>;
using chash_span = gsl::span<gsl::byte const, 20>;

// a mutable blob of data
// each entry has an id associated with it which must be unique among the entries it is stored with
class entry
{
public:
	entry(uint32_t id) : m_seq(0), m_id(id) {}

	static std::pair<entry, gsl::span<gsl::byte const>> parse(gsl::span<gsl::byte const> input);
	gsl::span<gsl::byte> serialize(gsl::span<gsl::byte> output) const;

	uint32_t id() const { return m_id; }
	std::vector<gsl::byte> const& value() const { return m_contents; }
	void assign(gsl::span<gsl::byte const> contents)
	{
		m_contents.assign(contents.begin(), contents.end());
		++m_seq;
	}

	// convenience function to save callers from having to do an
	// explicit to_bytes
	template <typename U, std::ptrdiff_t... Dimensions>
	void assign(gsl::span<U, Dimensions...> s)
	{
		assign(gsl::as_bytes(s));
	}

	bool operator==(entry const& o) const
	{
		return m_id == o.m_id
			&& m_seq == o.m_seq
			&& m_contents == o.m_contents;
	}

private:
	entry(int64_t seq, uint32_t id, std::vector<gsl::byte> content)
		: m_contents(std::move(content)), m_seq(seq), m_id(id) {}

	std::vector<gsl::byte> m_contents;
	int64_t m_seq;
	uint32_t const m_id;
};

// a token is associated with each piece of immutable data stored in a list
// it should be stored alongside the data and passed along with it to put
class list_token
{
public:
	friend class list_head;

	// input span must be extactly the size of the serialized token
	static list_token parse(gsl::span<gsl::byte const> input);
	gsl::span<gsl::byte> serialize(gsl::span<gsl::byte> output) const;

	hash const& next() const { return m_next; }

	bool operator==(list_token const& o) const
	{
		return m_next == o.m_next;
	}

private:
	list_token(hash next) : m_next(next) {}

	hash m_next;
};

// The head of a linked-list stored in the DHT. New items can only be inserted
// at the head of the list and list can only be retrieved starting at the head (LIFO).
class list_head
{
public:
	list_head()
	{
		m_head.fill(gsl::byte(0));
	}

	// input span must be extactly the size of the serialized list head
	static list_head parse(gsl::span<gsl::byte const> input);
	gsl::span<gsl::byte> serialize(gsl::span<gsl::byte> output) const;

	// add an item to the linked-list
	// the returned list_token should be stored with the contents and passed to put()
	list_token push_front(gsl::span<gsl::byte const> contents);

	// get the hash of the head of the list
	// this can be passed to get() to retrieve the first item in the list
	hash const& head() const { return m_head; }

	bool operator==(list_head const& o) const
	{
		return m_head == o.m_head;
	}

private:
	list_head(hash head) : m_head(head) {}

	hash m_head;
};

// takes a span of entries and write them out to a buffer
// returns a new span pointing to to one past the last byte used to store
// the entries
gsl::span<gsl::byte> serialize(gsl::span<entry const> entries, gsl::span<gsl::byte> output);

// parse a list of entries
// returns a span pointing to one past the last byte used to store the entries
gsl::span<gsl::byte const> parse(gsl::span<gsl::byte const> input, std::vector<entry>& entries);

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

void init(IDht& dht);
}
