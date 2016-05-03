#include "scout.hpp"
#include <memory>

namespace
{
	template <typename T, std::ptrdiff_t... Dimensions>
	gsl::span<gsl::byte const> extract(gsl::span<gsl::byte const> bytes, gsl::span<T, Dimensions...> v)
	{
		static_assert(std::is_trivial<std::decay_t<T>>::value);

		if (bytes.size_bytes() < v.size_bytes())
			throw std::length_error("bytes span smaller than destination");

		std::memcpy(v.data(), bytes.data(), v.size_bytes());

		// TODO: this causes a redundant bounds check
		return bytes.subspan(v.size_bytes());
	}
}
