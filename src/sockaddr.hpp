
#ifndef SOCKADDR_HPP__
#define SOCKADDR_HPP__

#include "sockaddr.h"
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/udp.hpp>

using boost::asio::ip::address;
using boost::asio::ip::address_v4;
using boost::asio::ip::address_v6;
using boost::asio::ip::udp;

SockAddr endpoint_to_sockaddr(udp::endpoint const& ep);
udp::endpoint sockaddr_to_endpoint(SockAddr const& saddr);

#endif
