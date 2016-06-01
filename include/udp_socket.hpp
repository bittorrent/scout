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

#ifndef UDP_SOCKET_HPP
# define UDP_SOCKET_HPP

#include <memory>
#include <boost/system/error_code.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/signal_set.hpp>
#include "utils.hpp" // for log_debug

// for _1, _2 etc.
using namespace std::placeholders;
namespace asio = boost::asio;
using boost::system::error_code;
using boost::asio::io_service;
using boost::asio::ip::udp;
using boost::asio::ip::address_v4;
using boost::asio::ip::address_v6;
using boost::asio::buffer;
using boost::asio::signal_set;

enum {
	ip_overhead = 20 + 8
};

struct udp_socket : public std::enable_shared_from_this<udp_socket>
{
	static std::shared_ptr<udp_socket> construct(io_service& ios)
	{
		return std::shared_ptr<udp_socket>(new udp_socket(ios));
	}

	static std::shared_ptr<udp_socket> construct(io_service& ios, udp::endpoint bindto)
	{
		return std::shared_ptr<udp_socket>(new udp_socket(ios, bindto));
	}

	udp_socket(udp_socket const& o) = delete;
	udp_socket& operator=(udp_socket const& o) = delete;

	udp_socket(udp_socket&& o)
		: m_socket(std::move(o.m_socket))
		, m_sender(std::move(o.m_sender))
		, m_handler(std::move(o.m_handler))
		, m_abort(std::move(o.m_abort))
	{
		std::memcpy(m_receive_buffer, o.m_receive_buffer, sizeof(m_receive_buffer));
	}

	typedef std::function<void(char *, size_t, udp::endpoint const&)> handler_t;

	void start(handler_t const& h, udp::endpoint const& ep, error_code& ec)
	{
		m_socket.bind(ep, ec);
		if (ec) return;

		m_bind_ep = ep;
		m_abort = false;

		m_handler = h;
		m_socket.async_receive_from(buffer(m_receive_buffer, sizeof(m_receive_buffer))
			, m_sender, std::bind(&udp_socket::on_receive, shared_from_this(), _1, _2));
	}

	int send_to(char const* buf, int len, udp::endpoint const& ep, error_code& ec)
	{
		int ret = m_socket.send_to(asio::buffer(buf, len), ep, 0, ec);
		if (ec && !m_abort && (ec == boost::system::errc::bad_file_descriptor
			|| ec == boost::system::errc::broken_pipe)) {

			// on iOS, when we wake up from background mode and our socket
			// has been reclaimed, we may get this error. Try to re-open it.
			reopen_socket(ec);
			if (ec) return -1;

			ret = m_socket.send_to(asio::buffer(buf, len), ep, 0, ec);
		}
		return ret;
	}

	udp::endpoint local_endpoint() const
	{
		error_code ec;
		return m_socket.local_endpoint(ec);
	}

	void cancel()
	{
#if _WIN32_WINNT <= 0x0502
		// XP and earlier do not support cancel
		m_socket.close();
#else
		m_socket.cancel();
#endif
		m_abort = true;
	}

	void close()
	{
		m_socket.close();
		m_abort = true;
	}

	void set_recv_buffer(std::size_t size)
	{
		boost::asio::socket_base::receive_buffer_size recv_size(size);
		m_socket.set_option(recv_size);
	}

private:

	// these constructors are private. use the construct functions
	udp_socket(io_service& ios)
		: m_socket(ios, udp::v4())
		, m_abort(false)
	{}

	udp_socket(io_service& ios, udp::endpoint bindto)
		: m_socket(ios, bindto)
		, m_abort(false)
	{}

	void reopen_socket(error_code& ec)
	{
		m_socket.close();
		m_socket.open(m_bind_ep.protocol(), ec);
		if (ec) return;
		m_socket.bind(m_bind_ep, ec);
		if (ec) return;
		m_socket.async_receive_from(buffer(m_receive_buffer, sizeof(m_receive_buffer))
			, m_sender, std::bind(&udp_socket::on_receive, shared_from_this(), _1, _2));
	}

	void on_receive(error_code const& ec, size_t bytes_transferred)
	{
		if (m_abort) {
			log_debug("udp_socket::on_receive aborted, exiting");
			return;
		}

		if (ec == boost::system::errc::bad_file_descriptor
			|| ec == boost::system::errc::broken_pipe
			|| ec == boost::system::errc::not_connected) {

			// on iOS, when we wake up from background mode and our socket
			// has been reclaimed, we may get this error. Try to re-open it and try
			// again.
			error_code ignore;
			reopen_socket(ignore);
			log_debug("udp_socket::on_receive re-opening socket failed: %s",
				ignore.message().c_str());
			return;
		}

		if (ec == asio::error::operation_aborted) {
			log_debug("udp_socket::on_receive canceled, exiting: %s", ec.message().c_str());
			return;
		}

		// pass on the packet to the handler
		if (!ec) m_handler((char *)m_receive_buffer, bytes_transferred, m_sender);
		else log_debug("udp_socket::on_receive ignoring error: %s", ec.message().c_str());

		// receive the next packet
		m_socket.async_receive_from(buffer(m_receive_buffer, sizeof(m_receive_buffer))
			, m_sender, std::bind(&udp_socket::on_receive, shared_from_this(), _1, _2));
	}

	// the buffer used for receiving packets into
	uint64_t m_receive_buffer[2000/8];

	// the socket we send and receive packets over
	udp::socket m_socket;

	// the sender's address of packets we receive
	udp::endpoint m_sender;

	// our address and port we've bound this socket to
	udp::endpoint m_bind_ep;

	// handler function to be called on incoming packets
	handler_t m_handler;

	// set to true if it's time to quit
	bool m_abort;
};

typedef std::shared_ptr<udp_socket> udp_socket_ptr;

#endif
