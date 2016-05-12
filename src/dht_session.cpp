#include "dht_session.hpp"

#include <random>
#include <sodium/crypto_sign.h>
#include <udp_utils.h>
#include "sockaddr.hpp"
#include "bencoding.h"

namespace
{
#if g_log_dht
	std::string filter(unsigned char const* p, int len)
	{
		std::string ret;
		ret.reserve(len);
		for (int i = 0; i < len; ++i)
		{
			if (std::isprint(p[i])) ret.push_back(p[i]);
			else ret.push_back('.');
		}
		return ret;
	}
#endif

	// This adapts our socket class to fit what ut_dht expects. All traffic via this
	// adaptor is DHT traffic.
	struct udp_socket_adaptor : UDPSocketInterface
	{
		udp_socket_adaptor(udp_socket* s) : m_socket(s), m_enabled(true) {}

		void set_enabled(bool e) { m_enabled = e; }

		void Send(const SockAddr& dest, cstr host, const byte *p, size_t len, uint32 flags = 0)
		{
			if (!m_enabled) return;
			// no support for sending to a hostname
			assert(false);
		}

		void Send(const SockAddr& dest, const byte *p, size_t len, uint32 flags = 0)
		{
			if (!m_enabled) return;

			udp::endpoint ep = sockaddr_to_endpoint(dest);
			error_code ec;
#if g_log_dht
			log_debug("DHT: ==> [%s:%d]: %s"
				, ep.address().to_string(ec).c_str(), ep.port(), filter(p, len).c_str());
#endif

			m_socket->send_to((char const*)p, len, ep, ec);
		}

		const SockAddr &GetBindAddr() const
		{
			udp::endpoint ep = m_socket->local_endpoint();
			m_bind_address = endpoint_to_sockaddr(ep);
			return m_bind_address;
		}

	private:

		mutable SockAddr m_bind_address;
		udp_socket* m_socket;
		bool m_enabled;
	};

	void save_dht_state(const byte* buf, int len)
	{
#if 0
		file f;
		std::string dht_file = get_dht_state_file();
		f.open(dht_file.c_str(), file::create | file::read_write);

		size_t written = f.write((char const*)buf, len);

		if (int(written) != len) {
			log_error("failed to write to \"%s\"; wrote %d out of %d bytes."
				, dht_file.c_str(), written, len);
		}
		f.truncate(len);
	}
	catch (boost::system::system_error& e) {
		error_code const& ec = e.code();
		log_error("failed to save DHT state to disk: (%d) %s"
			, ec.value(), ec.message().c_str());
	}
	catch (std::exception& e) {
		log_error("failed to save DHT state to disk: %s"
			, e.what());
#endif
	}

	// asks the client to load the DHT state into ent
	void load_dht_state(BencEntity* ent)
	{
#if 0
		read_bencoded_file(*static_cast<BencodedDict *>(ent), get_dht_state_file().c_str());
	}
	catch (std::exception& e) {
		log_error("failed to load DHT state: %s", e.what());
#endif
	}

	bool ed25519_verify(const unsigned char *signature,
		const unsigned char *message, size_t message_len,
		const unsigned char *key)
	{
		return 0 == crypto_sign_verify_detached(signature, message, message_len, key);
	}

	void ed25519_sign(unsigned char *signature, const unsigned char *message,
		size_t message_len, const unsigned char *key)
	{
		crypto_sign_detached(signature, nullptr, message, message_len, key);
	}

	// because std::to_string does not exist on Android
	std::string int_to_string(int val)
	{
		char buf[64];
		snprintf(buf, sizeof(buf), "%d", val);
		return std::string(buf);
	}
}

namespace scout
{

dht_session::dht_session()
	: m_socket(udp_socket::construct(m_ios))
	, m_dht_external_port(32768 + std::random_device()() % 16384)
	, m_external_ip(&sha1_fun)
	, m_dht_timer(m_ios)
	//, m_natpmp_timer(m_ios)
	, m_dht_rate_limit(8000)
{
	m_bootstrap_nodes.push_back(std::pair<std::string, int>("router.utorrent.com", 6881));
	m_bootstrap_nodes.push_back(std::pair<std::string, int>("router.bittorrent.com", 6881));
}

dht_session::~dht_session()
{
	m_ios.stop();
}

int dht_session::start()
{
	std::promise<int> promise;
	m_thread = std::move(std::thread(&dht_session::network_thread_fun, this, std::ref(promise)));
	return promise.get_future().get();
}

void dht_session::resolve_bootstrap_servers()
{
	// add router node to DHT, used for bootstrapping if no other nodes are known
	// remove nodes from the list once they've been resolved
	auto new_end = std::remove_if(m_bootstrap_nodes.begin(), m_bootstrap_nodes.end()
		, [&](std::pair<std::string, int> const& bsn)
	{
		struct addrinfo *result = nullptr;
		int r = getaddrinfo(bsn.first.c_str()
			, int_to_string(bsn.second).c_str()
			, nullptr, &result);
		if (r != 0)
		{
			log_error("Failed to resolve \"%s\": (%d) %s"
				, bsn.first.c_str(), r, strerror(r));
			return false;
		}
		else
		{
			log_debug("dht router is at \"%s\"", bsn.first.c_str());
			for (struct addrinfo* i = result; i != nullptr; i = i->ai_next)
			{
				// we only support IPv4
				if (i->ai_family != AF_INET) continue;
				sockaddr_in* v4 = (sockaddr_in*)i->ai_addr;
				m_dht->AddBootstrapNode(SockAddr(ntohl(v4->sin_addr.s_addr), ntohs(v4->sin_port)));
			}
			freeaddrinfo(result);
			return true;
		}
	});
	m_bootstrap_nodes.erase(new_end, m_bootstrap_nodes.end());
}

void dht_session::network_thread_fun(std::promise<int>& promise)
{
	udp_socket_adaptor socket_adaptor(m_socket.get());
	m_dht = create_dht(&socket_adaptor, &socket_adaptor
		, &save_dht_state, &load_dht_state, &m_external_ip);
	m_dht->SetSHACallback(&sha1_fun);
	m_dht->SetEd25519SignCallback(&ed25519_sign);
	m_dht->SetEd25519VerifyCallback(&ed25519_verify);
	m_dht->SetVersion("sc", 0, 1);
	// ping 6 nodes at a time, whenever we wake up
	m_dht->SetPingBatching(6);

	error_code ec;
	int num_attempts = 10;
	do
	{
		// try to bind the externally facing port to 'external_port'. Retry 'num_attempts'
		// times if it keeps failing.
		// the 'incoming_packet' is the handler that will be called every time
		// a new packet arrives
		m_socket->start(std::bind(&dht_session::incoming_packet, this, _1, _2, _3)
			, udp::endpoint(udp::v4(), m_dht_external_port), ec);

		if (!ec)
		{
			break;
		}
		// retry with a different port
		++m_dht_external_port;
		if (--num_attempts == 0)
		{
			log_error("Failed to bind DHT socket to port %d: (%d) %s"
				, m_dht_external_port, ec.value(), ec.message().c_str());
			promise.set_value(-1);
			return;
		}
		log_debug("port busy; retrying with dht port %d", m_dht_external_port);
	} while (true);

	resolve_bootstrap_servers();

	m_dht->Enable(true, m_dht_rate_limit);

	// the DHT timer calls the tick function on the DHT to keep it alive
	m_dht_timer.expires_from_now(std::chrono::seconds(1));
	m_dht_timer.async_wait(std::bind(&dht_session::on_dht_timer, this, _1));

	// update port mappings
	//update_mappings();

	//m_natpmp_timer.expires_from_now(seconds(natpmp_interval));
	//m_natpmp_timer.async_wait(std::bind(&communicator::on_natpmp_timer, this, _1));

	while (!is_quitting())
	{
		m_ios.run(ec);
		if (ec)
		{
			log_error("io_service::run: (%d) %s"
				, ec.value(), ec.message().c_str());
			break;
		}
		m_ios.reset();
	}
}

void dht_session::on_dht_timer(error_code const& ec)
{
	m_dht->Tick();
	m_dht_timer.expires_from_now(std::chrono::seconds(1));
	m_dht_timer.async_wait(std::bind(&dht_session::on_dht_timer, this, _1));
}

void dht_session::incoming_packet(char* buf, size_t len, udp::endpoint const& ep) try
{
	BencodedDict msg;
	if (!BencEntity::ParseInPlace((unsigned char*)buf, msg
		, (unsigned char*)buf + len)) {
		return;
	}

	SockAddr src = endpoint_to_sockaddr(ep);

	// don't forward packets to the DHT if we have disabled it.
	// don't tempt it to do things
	if (m_dht->IsEnabled()) {
		udp_socket_adaptor adaptor(m_socket.get());
		m_dht->handleReadEvent(&adaptor, (byte*)buf, len, src);
	}
}
catch (boost::system::system_error& e)
{
	error_code const& ec = e.code();
	log_error("error in incoming_packet: (%d) %s"
		, ec.value(), ec.message().c_str());
}
catch (std::exception& e)
{
	log_error("error in incoming_packet: %s", e.what());
}

}
