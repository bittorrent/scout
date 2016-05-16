#include "sockaddr.hpp"

SockAddr endpoint_to_sockaddr(udp::endpoint const& ep)
{
	SockAddr ret;
	if (ep.address().is_v4())
	{
		ret.set_addr4(ntohl(ep.address().to_v4().to_ulong()));
	}
	else
	{
		auto b = ep.address().to_v6().to_bytes();
		ret.from_compact(&b[0], b.size());
	}
	ret.set_port(ep.port());
	return ret;
}

udp::endpoint sockaddr_to_endpoint(SockAddr const& saddr)
{
	udp::endpoint ret;
	if (saddr.isv4())
	{
		ret = udp::endpoint(address_v4(saddr.get_addr4()), saddr.get_port());
	}
	else
	{
		address_v6::bytes_type b;
		saddr.compact(&b[0], false);
		ret = udp::endpoint(address_v6(b), saddr.get_port());
	}
	return ret;
}

