#include "dht.h"
#include <span.h>

class FakeDhtImpl : public IDht
{
public:
	FakeDhtImpl() {}
	~FakeDhtImpl() {}
	REFBASE;

	DhtSHACallback* _sha_callback;

	virtual bool handleReadEvent(UDPSocketInterface *socket, byte *buffer, size_t len, const SockAddr& addr) { return true; }
	virtual bool handleICMP(UDPSocketInterface *socket, byte *buffer, size_t len, const SockAddr& addr) { return true; }
	virtual void Tick() {}
	virtual void Vote(void *ctx, const sha1_hash* info_hash, int vote, DhtVoteCallback* callb) {}

	virtual void Put(const byte * pkey, const byte * skey, DhtPutCallback* put_callback,
		DhtPutCompletedCallback * put_completed_callback, DhtPutDataCallback* put_data_callback,
		void *ctx, int flags = 0, int64 seq = 0)
	{

	}

	std::vector<char> immutableData;
	bool immutableGetCalled = false;

	virtual sha1_hash ImmutablePut(const byte * data, size_t data_len,
		DhtPutCompletedCallback* put_completed_callback = nullptr, void *ctx = nullptr)
	{
		// save the data blob so we can check it later:
		immutableData.assign(data, data+data_len);
		put_completed_callback(ctx);
		sha1_hash hash;
		return hash;
	}

	virtual void ImmutableGet(sha1_hash target, DhtGetCallback* cb, void* ctx = nullptr)
	{
		immutableGetCalled = true;
		// return the data blob:
		cb(ctx, immutableData);
	}

	virtual void AnnounceInfoHash(const byte *info_hash, DhtAddNodesCallback *addnodes_callback,
		DhtPortCallback* pcb, cstr file_name, void *ctx, int flags = 0) {}

	virtual void SetId(byte new_id_bytes[20]) {}
	virtual void Enable(bool enabled, int rate) {}
	virtual void SetVersion(char const* client, int major, int minor) {}
	virtual void SetRate(int bytes_per_second) {}
	virtual void SetExternalIPCounter(ExternalIPCounter* ip) {}
	virtual void SetPacketCallback(DhtPacketCallback* cb) {}
	virtual void SetAddNodeResponseCallback(DhtAddNodeResponseCallback* cb) {}
	virtual void SetSHACallback(DhtSHACallback* cb) { _sha_callback = cb; }
	virtual void SetEd25519VerifyCallback(Ed25519VerifyCallback* cb) {}
	virtual void SetEd25519SignCallback(Ed25519SignCallback* cb) {}
	virtual void AddBootstrapNode(SockAddr const& addr) {}
	virtual void AddNode(const SockAddr& addr, void* userdata, uint origin) {}
	virtual bool CanAnnounce() { return true; }
	virtual void Close() {}
	virtual void Shutdown() {}
	virtual void Initialize(UDPSocketInterface *, UDPSocketInterface *) {}
	virtual bool IsEnabled() { return true;  }
	virtual void ForceRefresh() {}
	virtual void SetReadOnly(bool readOnly) {}
	virtual void SetPingFrequency(int seconds) {}
	virtual void SetPingBatching(int num_pings) {}
	virtual void EnableQuarantine(bool e) {}
	virtual bool ProcessIncoming(byte *buffer, size_t len, const SockAddr& addr) { return true; }
	virtual void DumpTracked() {}
	virtual void DumpBuckets() {}
	virtual int GetProbeQuota() { return 0; }
	virtual bool CanAddNode() { return true; }
	virtual int GetNumPeers() { return 0; }
	virtual bool IsBusy() { return true; }
	virtual int GetBootstrapState() { return 0; }
	virtual int GetRate() { return 0; }
	virtual int GetQuota() { return 0; }
	virtual int GetProbeRate() { return 0; }
	virtual int GetNumPeersTracked() { return 0; }
	virtual void Restart() {}
	virtual void GenerateId() {}
};