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
