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

#include <boost/asio/ip/address_v4.hpp>
#include <windows.h>
#include <wchar.h>
#include <natupnp.h>
#include <upnp.h>
#include <OleAuto.h>
#include "bencoding.h"
#include "snprintf.h"
#include "utypes.h"
#include "LoadLibraryList.h"
// kind of a hack
#include "Rpcsal.h"
#include "utils.hpp"
 
#ifndef __WINE__
#include <netfw.h>
#endif // __WINE__

#define LOGUPNP(X, ...) log_debug("upnp: " X, __VA_ARGS__)
#define LOGUPNP_ERROR(X, ...) log_error("upnp: " X, __VA_ARGS__)

std::string nat_friendly_name;
std::string nat_manufacturer;
std::string nat_model_name;
std::string nat_model_number;

typedef struct {
	VOID (WINAPI *VariantInit)(VARIANTARG FAR * pvarg);
	HRESULT (WINAPI *VariantClear)(VARIANTARG * pvarg);
	BSTR (WINAPI *SysAllocString)(const OLECHAR *  sz);
	VOID (WINAPI *SysFreeString)(BSTR  bstr);
	HRESULT (WINAPI *CoCreateInstance)(REFCLSID rclsid,LPUNKNOWN pUnkOuter,DWORD dwClsContext,REFIID riid,LPVOID * ppv);
	HRESULT (WINAPI *CoInitialize)(LPVOID pvReserved);
	VOID (WINAPI *CoUninitialize)();
	VOID (WINAPI *CoTaskMemFree)(LPVOID pv);
	HRESULT (WINAPI *CoGetObject)(LPCWSTR pszName, BIND_OPTS * pBindOptions, REFIID riid, LPVOID * ppv);
	int (WINAPI *StringFromGUID2)(REFGUID rguid, LPOLESTR lpsz, int cchMax);
	HRESULT (WINAPI *CLSIDFromProgID)(LPCOLESTR lpszProgID, LPCLSID lpclsid);
	HRESULT (WINAPI *OleRun)(LPUNKNOWN pUnknown);
	VOID (WINAPI *CoFreeUnusedLibrariesEx)(DWORD dwUnloadDelay,DWORD dwReserved);
} OleProcs;

OleProcs _ole_procs;

#define M(x) x "\0"
static const char _ole_files[] =
        M("oleaut32.dll")
        M("VariantInit")
        M("VariantClear")
        M("SysAllocString")
        M("SysFreeString")
        M("")
        M("ole32.dll")
        M("CoCreateInstance")
        M("CoInitialize")
        M("CoUninitialize")
        M("CoTaskMemFree")
        M("CoGetObject")
        M("StringFromGUID2")
        M("CLSIDFromProgID")
        M("OleRun")
        M("CoFreeUnusedLibrariesEx")
        M("");
#undef M

HRESULT InitializeCOM()
{
        if (!_ole_procs.CoInitialize) {
                if (!LoadLibraryList((void**)&_ole_procs, _ole_files)) {
                        return E_NOTIMPL;
                }
        }
        return _ole_procs.CoInitialize(NULL);
}

void UninitializeCOM()
{
        if (_ole_procs.CoUninitialize) {
                _ole_procs.CoUninitialize();
        }
}

class BSTR_stack_ptr
{
public:
	BSTR_stack_ptr() { ptr = NULL; }
	BSTR_stack_ptr(const OLECHAR* p) { ptr = _ole_procs.SysAllocString(p); }
	BSTR_stack_ptr(BSTR p, bool frombstring) { ptr = p; }
	~BSTR_stack_ptr() { if (ptr) _ole_procs.SysFreeString(ptr); }
	operator BSTR() const { return ptr; }
	bool operator==(BSTR p) { return p == ptr; }
	BSTR* operator&()
	{
		if (ptr) _ole_procs.SysFreeString(ptr);
		ptr = NULL;
		return &ptr;
	}

	BSTR ptr;
};

#if defined WIN32 || defined WANT_COM_INTERFACES_IN_POSIX_BUILD
// WARNING: this class assumes a donated reference - note the lack of AddRef
template <typename Interface>
class COM_stack_ptr
{
public:
	COM_stack_ptr() { ptr = NULL; }
	COM_stack_ptr(Interface* p) { ptr = p; }
	~COM_stack_ptr() { if (ptr) ptr->Release(); }
	Interface* operator->() const { return ptr; }
	operator Interface*() const { return ptr; }
	bool operator==(Interface* p) const { return p == ptr; }
	Interface** operator&()
	{
		if (ptr) ptr->Release();
		ptr = NULL;
		return &ptr;
	}
	Interface* get() { return ptr; }

	Interface* ptr;
};
#endif // defined WIN32 || defined WANT_COM_INTERFACES_IN_POSIX_BUILD

static bool AddNATPortMapping(uint InternalPort, uint *ExternalPort, BSTR Client, bool tcp,
			      bool &mapping_existed, std::wstring const& name,
			      boost::asio::ip::address_v4& external_ip)
{
	COM_stack_ptr<IUPnPNAT> nat;
	COM_stack_ptr<IStaticPortMappingCollection> spmc;
	COM_stack_ptr<IStaticPortMapping> spm;
	bool result = false;
	uint BasePort = *ExternalPort;
	uint MaxPort = BasePort + 255;

#ifndef __WINE__
	HRESULT hResult = _ole_procs.CoCreateInstance(__uuidof(UPnPNAT), NULL, CLSCTX_ALL, __uuidof(IUPnPNAT), (void**)&nat);

	if (SUCCEEDED(hResult) && nat) {
		hResult = nat->get_StaticPortMappingCollection(&spmc);
		if (SUCCEEDED(hResult) && spmc) {
			for(;;) {
				spm = NULL;
				BSTR_stack_ptr proto(tcp?L"TCP":L"UDP");
				hResult = spmc->get_Item(BasePort, proto, &spm);
				if (!SUCCEEDED(hResult) || spm == NULL)
					break;

				/* External port is already used ... check to see if it matches */
				VARIANT_BOOL enabled;
				spm->get_Enabled(&enabled);
				if (enabled) {
					BSTR_stack_ptr mapped_client;
					hResult = spm->get_InternalClient(&mapped_client);
					if (SUCCEEDED(hResult) &&  _wcsicmp(mapped_client, Client) == 0) {
						long port;
						hResult = spm->get_InternalPort(&port);
						if (SUCCEEDED(hResult) && port == InternalPort) {
							hResult = spm->get_ExternalPort(&port);
							if (SUCCEEDED(hResult)) {
								*ExternalPort = port;
								result = true;
								mapping_existed = true;
								return result;
							}
						}
					}
				}

				/* External port is already used ... try to find another one */
				*ExternalPort = ++BasePort;
				if (BasePort > MaxPort) {
					return result;
				}
			}
			spm = NULL;

			// XXX Was this supposed to be UTF-8 encoded? Why to_unicode?
			BSTR_stack_ptr bname(name.c_str());

			BSTR_stack_ptr proto(tcp ? L"TCP" : L"UDP");
			hResult = spmc->Add(BasePort, proto, InternalPort, Client, TRUE, bname, &spm);
			if (SUCCEEDED(hResult) && spm) {
				/* Add new NAT port mapping */
				BSTR _external_ip;
				if (spm->get_ExternalIPAddress(&_external_ip) == S_OK) {
					// TODO: is this really correct? I often see 0.0.0.0 in UPnP records
					// if it is, use TorrentSession::GotExternalIP
					char buf[32];
					size_t n;
					wcstombs_s(&n, buf, 32, _external_ip, wcslen(_external_ip));
					assert(n == wcslen(_external_ip) + 1);
					external_ip = boost::asio::ip::address_v4::from_string(buf);
					_ole_procs.SysFreeString(_external_ip);
				}
				result = true;
			}
		}
	}
#endif // __WINE__

	return result;
}

bool RemoveNATPortMapping(WORD ExternalPort, bool tcp)
{
	bool result = false;
	COM_stack_ptr<IUPnPNAT> nat;
	COM_stack_ptr<IStaticPortMappingCollection> spmc;

#ifndef __WINE__
	HRESULT hResult = _ole_procs.CoCreateInstance(__uuidof(UPnPNAT), NULL, CLSCTX_ALL, __uuidof(IUPnPNAT), (void**)&nat);

	if (SUCCEEDED(hResult) && nat) {
		hResult = nat->get_StaticPortMappingCollection(&spmc);
		if (SUCCEEDED(hResult) && spmc) {
			BSTR_stack_ptr proto(tcp?L"TCP":L"UDP");
			spmc->Remove(ExternalPort, proto);
			result = true;
		}
	}
#endif // __WINE__
	return result;
}

static uint UPnPSetPortMapping(uint32 ip, uint16 port, bool tcp, bool &mapping_existed, std::wstring const& name, boost::asio::ip::address_v4& external_ip)
{
	boost::asio::ip::address_v4 ipaddr(ip);
	tstring ip_str(_T(ipaddr.to_string().c_str()));
	wchar_t buf[32];
	size_t n;
	mbstowcs_s(&n, buf, 32, ip_str.c_str(), ip_str.size());
	BSTR_stack_ptr client(buf);

	// This is the Port which will be used externally by the router and
	// which is opened to the internet.
	uint ExternalPort = port;
	if (!AddNATPortMapping(port, &ExternalPort, client, tcp, mapping_existed, name, external_ip)) {
		return 0;
	}

	return ExternalPort;
}


bool UPnPMapPort(uint32 ip, uint16 internal_port, uint16* tcp_port, uint16* udp_port, std::wstring const& name, boost::asio::ip::address_v4& external_ip)
{
	bool success = true;

	// these static variables are messy!
	if (tcp_port && *tcp_port != internal_port &&
		RemoveNATPortMapping(*tcp_port, true)) {
		LOGUPNP("UPnP(XP): Removed TCP port %d", *tcp_port);
		*tcp_port = 0;
	} else {
		success = false;
	}

	if (udp_port && *udp_port && *udp_port != internal_port &&
		RemoveNATPortMapping(*udp_port, false)) {
		LOGUPNP("UPnP(XP): Removed UDP port %d", *udp_port);
		*udp_port = 0;
	} else {
		success = false;
	}

	if (!internal_port)
		return success;

	if (!ip)
		return false;

	// failed unmapping but succesful mapping is still success
	success = true;

	for (bool tcp = true;;tcp = false) {
		if (tcp && !tcp_port)
			continue;
		if (!tcp && !udp_port)
			break;
		bool mapping_existed = false;
		uint16 port = UPnPSetPortMapping(ip, internal_port, tcp, mapping_existed, name, external_ip);
		if (port) {
			if (mapping_existed) {
				LOGUPNP("UPnP(XP): %s port %d -> %I:%d is already mapped. Not re-mapping.",
					tcp?"TCP":"UDP", port, ip, internal_port);
			} else {
				LOGUPNP("UPnP(XP): %s port %d -> %I:%d mapped successfully.",
						tcp?"TCP":"UDP", port, ip, internal_port);
			}
			if (tcp) {
				*tcp_port = port;
			} else {
				*udp_port = port;
			}
		} else {
			// don't log, let the caller decide
			//LOGUPNP_ERROR("Unable to map UPnP port to %I:%d", ip, internal_port);
			success = false;
		}
		if (!tcp)
			break;
	}

	return success;
}

static void bstr_to_string(BSTR b, std::string& result)
{
  size_t buf_len = wcslen(b) + 1;
  char* buf = new char[buf_len];
  size_t n;
  wcstombs_s(&n, buf, buf_len, b, buf_len - 1);
  assert(n == buf_len - 1);
  result = std::string(buf);
  delete[] buf;
}

// Query and save the internet gateway device after we've successfully mapped via Windows API
// This needs to be in a UI-independent thread, as it blocks
void UPnPSaveGatewayInfo()
{
	// Loosely based on references/examples:
	// http://www.codeproject.com/KB/IP/PortForward.aspx
	// http://msdn2.microsoft.com/en-us/library/aa382297(VS.85).aspx
	IUPnPDeviceFinder* pDeviceFinder = NULL;
	IUPnPDevices* pFoundDevices = NULL;

#ifndef __WINE__
//	HRESULT hResult = _ole_procs.CoCreateInstance(CLSID_UPnPDeviceFinder, NULL, CLSCTX_ALL, IID_IUPnPDeviceFinder, (void**) &pDeviceFinder);
	HRESULT hResult = _ole_procs.CoCreateInstance(__uuidof(UPnPDeviceFinder), NULL, CLSCTX_ALL, _uuidof(IUPnPDeviceFinder), (void**) &pDeviceFinder);
	if (SUCCEEDED(hResult) && pDeviceFinder) {
		BSTR_stack_ptr typeURI(L"urn:schemas-upnp-org:device:InternetGatewayDevice:1");
		hResult = pDeviceFinder->FindByType(typeURI, 0, &pFoundDevices);
		// Traversal: http://msdn2.microsoft.com/en-us/library/aa381156.aspx
		if (SUCCEEDED(hResult) && pFoundDevices) {
			IUnknown* pUnknown = NULL;
			hResult = pFoundDevices->get__NewEnum(&pUnknown);
			if (SUCCEEDED(hResult) && pUnknown) {
			    IEnumVARIANT* pEnumVariant = NULL;
				hResult = pUnknown->QueryInterface(IID_IEnumVARIANT, (void**) &pEnumVariant);
				if (SUCCEEDED(hResult) && pEnumVariant) {
					VARIANT v;
					_ole_procs.VariantInit(&v);
					pEnumVariant->Reset();
					while (S_OK == pEnumVariant->Next(1, &v, NULL))	{
						IUPnPDevice* pDevice = NULL;
						IDispatch* pdispDevice = V_DISPATCH(&v);
//						if (SUCCEEDED(pdispDevice->QueryInterface(IID_IUPnPDevice, (void **) &pDevice))) {
						if (SUCCEEDED(pdispDevice->QueryInterface(__uuidof(IUPnPDevice), (void **) &pDevice))) {
							// Do something interesting with pDevice
							BSTR b = NULL;
							char* buf = NULL;
							if (SUCCEEDED(pDevice->get_FriendlyName(&b)) && b) {
								bstr_to_string(b, nat_friendly_name);
								_ole_procs.SysFreeString(b);
							}
							if (SUCCEEDED(pDevice->get_ManufacturerName(&b)) && b) {
								bstr_to_string(b, nat_manufacturer);
								_ole_procs.SysFreeString(b);
							}
							if (SUCCEEDED(pDevice->get_ModelName(&b)) && b) {
								bstr_to_string(b, nat_model_name);
								_ole_procs.SysFreeString(b);
							}
							if (SUCCEEDED(pDevice->get_ModelNumber(&b)) && b) {
								bstr_to_string(b, nat_model_number);
								_ole_procs.SysFreeString(b);
							}
							break;
						}
						_ole_procs.VariantClear(&v);
					}
					pEnumVariant->Release();
				}
				pUnknown->Release();
			}
			pFoundDevices->Release();
		}
		pDeviceFinder->Release();
	}
#endif // __WINE__
}
