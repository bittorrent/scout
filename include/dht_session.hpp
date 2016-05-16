#ifndef BITTORRENT_DHT_SESSION_HPP
#define BITTORRENT_DHT_SESSION_HPP

#include <thread>
#include <future>
#include <boost/asio/io_service.hpp>
#include <boost/asio/steady_timer.hpp>
#include <dht.h>
#include <ExternalIPCounter.h>
#include "udp_socket.hpp"

namespace scout
{

class dht_session
{
public:
	dht_session();
	~dht_session();

	int start();

private:
	bool is_quitting() const { return false; }
	void resolve_bootstrap_servers();
	void network_thread_fun(std::promise<int>& promise);
	void on_dht_timer(error_code const& ec);
	void incoming_packet(char* buf, size_t len, udp::endpoint const& ep);

	boost::asio::io_service m_ios;
	std::uint16_t m_dht_external_port;
	ExternalIPCounter m_external_ip;
	std::shared_ptr<udp_socket> m_socket;
	std::thread m_thread;
	smart_ptr<IDht> m_dht;
	boost::asio::steady_timer m_dht_timer;
	//boost::asio::steady_timer m_natpmp_timer;
	std::vector<std::pair<std::string, int>> m_bootstrap_nodes;
	int m_dht_rate_limit;
};

} // namespace scout

#endif
