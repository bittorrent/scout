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

#include "dht_session.hpp"

#include <random>
#include <sodium/crypto_sign.h>
#include <udp_utils.h>
#include "sockaddr.hpp"
#include "bencoding.h"
#include "file.hpp"

#include "libnatpmp/natpmp.h"
#include "libminiupnpc/miniupnpc.h"
#include "libminiupnpc/upnpcommands.h"
#include "libminiupnpc/upnperrors.h"
#include "upnp-portmap.h"

#ifdef _WIN32
#include <Iphlpapi.h>
#endif

namespace
{
	using boost::system::system_category;

	enum
	{
		natpmp_interval = 480
	};

	template <class F>
	struct scope_guard
	{
		scope_guard(F const& f) : m_f(f), m_valid(true) {}

		scope_guard(scope_guard const & sg) = delete;
		scope_guard& operator=(scope_guard const& sg) = delete;

		scope_guard(scope_guard&& sg)
			: m_f(std::move(sg.m_f))
			, m_valid(true) {
			sg.m_valid = false;
		}

		void disarm() { m_valid = false; }

		~scope_guard() { if (m_valid) m_f(); }
		F m_f;
		bool m_valid;

	};

	template <class F>
	scope_guard<F> make_guard(F f) { return scope_guard<F>(f); }

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

	// This adapts our socket class to fit what btdht expects. All traffic via this
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

	void save_dht_state(const byte* buf, int len) try
	{
		file f;
		std::string dht_file = "dht.dat";
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
	}

	void bdecode_buffer_with_hash(BencodedDict& dict, char const* buffer, int size)
	{
		unsigned char const* pos = BencEntity::Parse((unsigned char *)buffer, dict
			, (unsigned char*)buffer + size);

		if (pos < (unsigned char*)buffer) {
			throw std::runtime_error("failed to parse bencoding");
		}

		// if there are 24 bytes remaining at the end of the file,
		// consider it a hash and verify it
		size -= (pos - (unsigned char*)buffer);
		if (size >= 24
			&& memcmp(pos + 20, "hash", 4) == 0) {

			// there is a hash at the end of the file
			// verify it
			sha1_hash hash = sha1_fun((byte const*)buffer, pos - (unsigned char*)buffer);

			if (memcmp(&hash.value, pos, 20) != 0) {
				throw std::runtime_error("invalid check-sum");
			}
		}
	}

	// read and parse a bencoded dictionary from a given file:
	void read_bencoded_file(BencodedDict& dict, file& f)
	{
		int size = int(f.size());

		// It's possible that we were asked to read an empty file!
		if (size == 0) {
			throw std::runtime_error("empty file");
		}

		std::vector<char> buffer(size);

		auto g = make_guard([&] {
			// clear the memory before freeing
			memset(&buffer[0], 0, buffer.size());
		});

		int ret = f.read(&buffer[0], size); // read the file

		assert(ret == size);
		if (ret != size) {
			throw std::runtime_error("failed to read entire file");
		}

		bdecode_buffer_with_hash(dict, &buffer[0], buffer.size());
	}

	// This version of read_bencoded_file is provided for classes other
	// than settings_file to read bencoded files from a BencodedDict
	// This version DOES close the file after it is done
	void read_bencoded_file(BencodedDict& dict, char const* filename)
	{
		// First, try to open filename as an empty file
		file f(filename, file::read_only);
		read_bencoded_file(dict, f);
	}

	// asks the client to load the DHT state into ent
	void load_dht_state(BencEntity* ent) try
	{
		read_bencoded_file(*static_cast<BencodedDict *>(ent), "dht.dat");
	}
	catch (std::exception& e) {
		log_error("failed to load DHT state: %s", e.what());
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

	// TODO: it would be nice to return the local IPs in priority order. i.e. the
	// ones that seems most relevant first. for instance, NICs set upt just to
	// talk to a vartual machine should probably be at the end.
#ifdef _WIN32
	std::vector<address> get_local_ip(error_code& ec)
	{
		std::vector<address> ret;
		DWORD index = 0;
		static const u_long arbitrary_internet_address = 0x04040404;
		int best = GetBestInterface(arbitrary_internet_address, &index);
		if (best != NO_ERROR) {
			ec = error_code(GetLastError(), system_category());
			return ret;
		}

		uint64_t buffer[2048];
		PMIB_IPADDRTABLE pIPAddrTable = (PMIB_IPADDRTABLE)buffer;
		unsigned long size = sizeof(buffer);
		if (GetIpAddrTable(pIPAddrTable, &size, 0) == NO_ERROR) {
			for (uint i = 0; i < pIPAddrTable->dwNumEntries; i++) {
				if (pIPAddrTable->table[i].dwIndex == index) {
					uint32_t ip = ntohl(pIPAddrTable->table[i].dwAddr);
					ret.push_back(address_v4(ip));
				}
			}
		}

		if (ret.empty())
			ec = error_code(ERROR_FILE_NOT_FOUND, system_category());

		return ret;
	}
#elif defined __linux__ && ! defined ANDROID
	std::vector<address> get_local_ip(error_code& ec)
	{
		std::vector<address> ret;
		int s = socket(AF_INET, SOCK_DGRAM, 0);
		if (s < 0)
		{
			ec = error_code(errno, asio::error::system_category);
			return ret;
		}

		ifaddrs *ifaddr;
		if (getifaddrs(&ifaddr) == -1)
		{
			ec = error_code(errno, asio::error::system_category);
			close(s);
			return ret;
		}

		for (ifaddrs* ifa = ifaddr; ifa; ifa = ifa->ifa_next)
		{
			if (ifa->ifa_addr == 0) continue;
			if ((ifa->ifa_flags & IFF_UP) == 0) continue;

			int family = ifa->ifa_addr->sa_family;
			if (family == AF_INET)
			{
				if (ifa->ifa_addr->sa_family != AF_INET
					//				&& ifa->ifa_addr->sa_family != AF_INET6
					)
					continue;

				address a = sockaddr_to_address(ifa->ifa_addr);
				if (a.is_loopback()) continue;
				ret.push_back(a);
				break;
			}
		}
		close(s);
		freeifaddrs(ifaddr);
		return ret;
	}

#else
	std::vector<address> get_local_ip(error_code& ec)
	{
		std::vector<address> ret;
		int s = socket(AF_INET, SOCK_DGRAM, 0);
		if (s < 0)
		{
			ec = error_code(errno, asio::error::system_category);
			return ret;
		}
		ifconf ifc;
		// make sure the buffer is aligned to hold ifreq structs
		ifreq buf[40];
		ifc.ifc_len = sizeof(buf);
		ifc.ifc_buf = (char*)buf;
		if (ioctl(s, SIOCGIFCONF, &ifc) < 0)
		{
			ec = error_code(errno, asio::error::system_category);
			close(s);
			return ret;
		}

		char *ifr = (char*)ifc.ifc_req;
		int remaining = ifc.ifc_len;

		while (remaining > 0)
		{
			ifreq const& item = *reinterpret_cast<ifreq*>(ifr);

#ifdef _SIZEOF_ADDR_IFREQ
			int current_size = _SIZEOF_ADDR_IFREQ(item);
#elif (defined __APPLE__ && defined __MACH__) || defined __FreeBSD__ || defined __NetBSD__ \
	|| defined __OpenBSD__ || defined __bsdi__ || defined __DragonFly__ \
	|| defined __FreeBSD_kernel__
			int current_size = item.ifr_addr.sa_len + IFNAMSIZ;
#else
			int current_size = sizeof(ifreq);
#endif

			if (remaining < current_size) break;

			if (item.ifr_addr.sa_family != AF_INET
				//			&& item.ifr_addr.sa_family != AF_INET6
				)
			{
				ifr += current_size;
				remaining -= current_size;
				continue;
			}

			address a = sockaddr_to_address(&item.ifr_addr);
			if (a.is_loopback()) {
				error_code ignore;
				ifr += current_size;
				remaining -= current_size;
				continue;
			}
			if (std::none_of(ret.begin(), ret.end(), [&](address const& addr)
			{ return addr == a; })) {
				error_code ignore;
				ret.push_back(a);
			}
			else {
				error_code ignore;
			}
			ifr += current_size;
			remaining -= current_size;
		}
		close(s);
		return ret;
	}
#endif

#ifdef _WIN32
	uint16 upnp_tcp_port = 0;
	uint16 upnp_udp_port = 0;
#endif

	void map_upnp(int port, std::vector<upnp_mapping>& mappings)
	{
		log_debug("adding UPnP port mapping");
#ifdef _WIN32
		error_code ec;
		// get our IP address from our main interface
		std::vector<address> my_ips = get_local_ip(ec);
		if (ec)
		{
			log_error("Failed to get local IP address (%d) %s"
				, ec.value(), ec.message().c_str());
		}
		else
		{
			for (auto const& a : my_ips) {
				log_debug("local ip: %s", a.to_string(ec).c_str());

				address_v4 upnp_external_ip;
				UPnPMapPort(a.to_v4().to_ulong(), port
					, &upnp_tcp_port, &upnp_udp_port, L"BitTorrent Bleep", upnp_external_ip);
			}
		}
#endif

		UPNPDev* devlist = nullptr;

		// UPnP stuff
		int error = 0;
		log_debug("looking for UPnP gateway devices");
		devlist = upnpDiscover(1000, 0, 0, 0, 0, &error);
		log_debug("List of UPNP devices found on the network:");
		for (UPNPDev* device = devlist; device; device = device->pNext)
		{
			log_debug(" desc: %s", device->descURL);
			log_debug(" st:   %s", device->st);

			UPNPUrls urls;
			IGDdatas data;
			char lanaddr[64];
			// 1 is connected IGD
			if (UPNP_GetValidIGD(device, &urls, &data, lanaddr, sizeof(lanaddr)) == 1)
			{
				char port_str[30];
				snprintf(port_str, sizeof(port_str), "%d", port);
				int r = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype,
					port_str, port_str, lanaddr, "BitTorrent Bleep", "UDP", "*", "0");

				if (r != UPNPCOMMAND_SUCCESS) {
					log_error("AddPortMapping(%s, %s) failed with code %d (%s)",
						port_str, lanaddr, r, strupnperror(r));
				}
				else {
					log_debug("UPnP port mapping successful");
					mappings.push_back(upnp_mapping(urls.controlURL, data.first.servicetype));
				}
			}
		}
	}

	void unmap_upnp(int port, std::vector<upnp_mapping>& mappings)
	{
		log_debug("deleting UPnP port mapping");

		char port_str[30];
		snprintf(port_str, sizeof(port_str), "%d", port);

		for (auto& m : mappings)
		{
			log_debug(" URL:  %s", m.controlURL.c_str());
			log_debug(" st:   %.*s", sizeof(m.servicetype), m.servicetype);

			int r = UPNP_DeletePortMapping(m.controlURL.c_str(), m.servicetype,
				port_str, "UDP", "*");

			if (r != UPNPCOMMAND_SUCCESS) {
				log_error("DeletePortMapping(%s) failed with code %d (%s)",
					port_str, r, strupnperror(r));
			}
			else {
				log_debug("UPnP port mapping deletion successful");
			}
		}

		mappings.clear();

#ifdef _WIN32
		RemoveNATPortMapping(upnp_tcp_port, true);
		RemoveNATPortMapping(upnp_udp_port, false);
#endif
	}

	// timeout is in seconds. 0 means remove mapping
	void map_natpmp(int port, int time_to_live, scout::dht_session::run_state const& state
		, bool& is_natpmp_mapped) {
		bool is_quitting = state == scout::dht_session::QUITTING;
		if (is_quitting && !is_natpmp_mapped) return;
		natpmp_t natpmp_state;
		initnatpmp(&natpmp_state, 0, 0);

		auto g = make_guard([&] {
			closenatpmp(&natpmp_state);
			log_debug("NAT-PMP: port mapping complete");
		});

		if (time_to_live > 0) {
			log_debug("NAT-PMP: new port mapping %d", port);
		}
		else {
			log_debug("NAT-PMP: deleting port mapping %d", port);
			if (!is_natpmp_mapped) return;
		}

		int r = sendnewportmappingrequest(&natpmp_state, NATPMP_PROTOCOL_UDP,
			port, port, time_to_live);

		natpmpresp_t response;
		struct timeval timeout;
		memset(&timeout, 0, sizeof(timeout));
		fd_set fds;
		do {
			FD_ZERO(&fds);
			FD_SET(natpmp_state.s, &fds);
			int r = getnatpmprequesttimeout(&natpmp_state, &timeout);
			if (r != 0) {
				log_error("getnatpmprequesttimeout() failed: %d\n", r);
				return;
			}
			// yes. this can happen. it's stupid
			if (timeout.tv_sec < 0) timeout.tv_sec = 1;
			if (timeout.tv_usec < 0) timeout.tv_usec = 0;

			assert(timeout.tv_sec < 4);

			if (is_quitting && !is_natpmp_mapped) return;
			// this select appears to take up to 8 seconds
			r = select(FD_SETSIZE, &fds, NULL, NULL, &timeout);
			if (r < 0) {
				log_error("select()");
				return;
			}
			r = readnatpmpresponseorretry(&natpmp_state, &response);
			int sav_errno = errno;
			if (r < 0 && r != NATPMP_TRYAGAIN) {
				log_error("NAT-PMP failed : %s", strnatpmperr(r));
				log_error("  errno=%d '%s'",
					sav_errno, strerror(sav_errno));
			}
		} while (r == NATPMP_TRYAGAIN);
		if (r >= 0) is_natpmp_mapped = !is_natpmp_mapped;
	}
}

namespace scout
{

struct ip_change_observer_session : ip_change_observer
{
	dht_session * m_ses;
	ip_change_observer_session(dht_session* c) : m_ses(c) {}

	void on_ip_change(SockAddr const & new_ip)
	{
		m_ses->on_ip_changed(sockaddr_to_endpoint(new_ip));
	}
};

dht_session::dht_session()
	: m_socket(udp_socket::construct(m_ios))
	, m_dht_external_port(32768 + std::random_device()() % 16384)
	, m_state(INITIAL)
	, m_external_ip(&sha1_fun)
	, m_dht_timer(m_ios)
	, m_natpmp_timer(m_ios_worker)
	, m_is_natpmp_mapped(false)
	, m_dht_rate_limit(8000)
{
	m_bootstrap_nodes.push_back(std::pair<std::string, int>("router.utorrent.com", 6881));
	m_bootstrap_nodes.push_back(std::pair<std::string, int>("router.bittorrent.com", 6881));
}

dht_session::~dht_session()
{
	stop();
}

int dht_session::start()
{
	if (m_state != INITIAL) return 0;
	m_state = RUNNING;
	std::promise<int> promise;
	m_thread = std::move(std::thread(&dht_session::network_thread_fun, this, std::ref(promise)));
	return promise.get_future().get();
}

void dht_session::stop()
{
	if (m_state != RUNNING) return;
	m_state = QUITTING;
	m_dht->Shutdown();
	m_dht_timer.cancel();
	m_ios.stop();
	m_thread.join();
}

void dht_session::synchronize(secret_key_span shared_key, std::vector<entry> entries
	, entry_updated entry_cb, finalize_entries finalize_cb, sync_finished finished_cb)
{
	m_ios.post([=, captured_entries = std::move(entries)]()
	{
		::synchronize(*m_dht, shared_key, captured_entries, entry_cb, finalize_cb, finished_cb);
	});
}

void dht_session::put(list_token const& token, gsl::span<gsl::byte const> contents
	, put_finished finished_cb)
{
	m_ios.post([=]()
	{
		::put(*m_dht, token, contents, finished_cb);
	});
}

void dht_session::get(hash_span address, item_received received_cb)
{
	m_ios.post([=]()
	{
		::get(*m_dht, address, received_cb);
	});
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

void dht_session::update_mappings()
{
	m_ios_worker.post(std::bind(&map_upnp
		, m_dht_external_port, std::ref(m_upnp_mappings)));

	m_ios_worker.post(std::bind(&map_natpmp, m_dht_external_port
		, natpmp_interval * 3 / 2, std::cref(m_state)
		, std::ref(m_is_natpmp_mapped)));
}

void dht_session::network_thread_fun(std::promise<int>& promise)
{
#ifdef _WIN32
	COM_stack_init com;
	if (!com) {
		error_code ec(GetLastError(), system_category());
		log_error("failed to initialize COM: (%d) %s"
			, ec.value(), ec.message().c_str());
	}
#else
	// the default action for SIGPIPE is to terminate the process.
	// we don't want that, just ignore it.
	signal(SIGPIPE, SIG_IGN);
#endif

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
	update_mappings();

	m_natpmp_timer.expires_from_now(std::chrono::seconds(natpmp_interval));
	m_natpmp_timer.async_wait(std::bind(&dht_session::on_natpmp_timer, this, _1));

	std::unique_ptr<io_service::work> work_ios(new io_service::work(m_ios_worker));
	m_worker_thread = std::move(std::thread([&]() { m_ios_worker.run(); }));

	promise.set_value(0);

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

	m_natpmp_timer.cancel();
	m_ios_worker.stop();
	m_worker_thread.join();
}

void dht_session::on_dht_timer(error_code const& ec)
{
	m_dht->Tick();
	m_dht_timer.expires_from_now(std::chrono::seconds(1));
	m_dht_timer.async_wait(std::bind(&dht_session::on_dht_timer, this, _1));
}

void dht_session::on_natpmp_timer(error_code const& ec)
{
	if (ec)
	{
		if (ec != boost::asio::error::operation_aborted) {
			log_error("natpmp timer failed: (%d) %s"
				, ec.value(), ec.message().c_str());
		}
		return;
	}

	if (is_quitting()) return;

	// post the nat-pmp task to be performed on the worker thread:
	m_ios_worker.post(std::bind(&map_natpmp
		, m_dht_external_port, natpmp_interval * 3 / 2, std::cref(m_state)
		, std::ref(m_is_natpmp_mapped)));

	m_natpmp_timer.expires_from_now(std::chrono::seconds(natpmp_interval));
	m_natpmp_timer.async_wait(std::bind(&dht_session::on_natpmp_timer
		, this, _1));
}

void dht_session::on_ip_changed(udp::endpoint const& new_ip)
{
	update_mappings();
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
		if (m_dht->handleReadEvent(&adaptor, (byte*)buf, len, src))
		{
#if g_log_dht
			error_code ec;
			log_debug("DHT: <== [%s:%d]: %s"
				, ep.address().to_string(ec).c_str(), ep.port()
				, filter((unsigned char const*)buf, len).c_str());
#endif
		}
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
