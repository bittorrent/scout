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

private:
	std::vector<gsl::byte> m_contents;
	int64_t m_seq;
	uint32_t const m_id;
};

class list_token
{
public:
	explicit list_token(hash next) : m_next(next) {}
	hash const& next() const { return m_next; }
private:
	hash m_next;
};

class list_head
{
public:
	list_token push_front(gsl::span<gsl::byte const> contents);
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

using entry_updated = std::function<void(std::vector<entry>::iterator e)>;
using finalize_entries = std::function<void(std::vector<entry>& entries)>;
using sync_finished = std::function<void()>;
using item_received = std::function<void(list_token const& token, gsl::span<gsl::byte const> contents)>;
using put_finished = std::function<void()>;

void synchronize(IDht& dht, secret_key_span shared_key, std::vector<entry>& entries
	, entry_updated entry_cb, finalize_entries finalize_cb, sync_finished finished_cb);
void put(IDht& dht, list_token const& token, gsl::span<gsl::byte const> contents
	, put_finished finished_cb);
void get(IDht& dht, hash_span address, item_received received_cb);

}
