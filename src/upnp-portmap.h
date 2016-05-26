#ifndef __CLIENTUPNP_H__
#define __CLIENTUPNP_H__

#include <string>

HRESULT InitializeCOM();
void UninitializeCOM();

class COM_stack_init
{
public:
	COM_stack_init() { result = InitializeCOM(); }
	~COM_stack_init() { UninitializeCOM(); }
	operator bool() { return SUCCEEDED(result); }
	HRESULT result;
};

bool UPnPMapPort(uint32 ip, uint16 internal_port, uint16* tcp_port, uint16* udp_port
	, std::wstring const& name, boost::asio::ip::address_v4& external_ip);
bool RemoveNATPortMapping(WORD ExternalPort, bool tcp);

#endif //__CLIENTUPNP_H__
