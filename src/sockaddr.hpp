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
