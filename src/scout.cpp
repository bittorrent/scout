#include "scout.hpp"
#include <boost/endian/arithmetic.hpp>
#include <memory>
#include <cassert>

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

} // namespace scout
