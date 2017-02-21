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

#include <iostream>
#include <cstdio>
#include <system_error>
#include <sodium/crypto_scalarmult.h>
#include <scout.hpp>
#include <dht_session.hpp>

namespace
{
	const static char hex_alphabet[] = "0123456789abcdef";

	std::string base16_encode(std::string s)
	{
		std::string ret;
		ret.resize(s.size() * 2);
		for (int i = 0; i < int(s.size()); ++i)
		{
			ret[i * 2] = hex_alphabet[(s[i] >> 4) & 0xf];
			ret[i * 2 + 1] = hex_alphabet[s[i] & 0xf];
		}
		return ret;
	}

	std::string base16_decode(std::string s)
	{
		std::string ret;
		ret.resize((s.size() + 1) / 2);
		// the & ~1 is to round down to an even multiple of
		// 2, since the loop requires that.
		for (int i = 0; i < (s.size() & ~1); i += 2)
		{
			ret[i / 2] = (strchr(hex_alphabet, s[i]) - hex_alphabet) << 4;
			ret[i / 2] |= (strchr(hex_alphabet, s[i + 1]) - hex_alphabet) & 0xf;
		}
		return ret;
	}
}

void usage()
{
	std::cerr << "Usage: client_test <command> [args]\n"
		"Commands:\n"
		"gen-key <file name>            - generate a key pair and store it in the specified file\n"
		"dump-key <file name>           - print the public key from the specified file\n"
		"sync <file name> <public key> <entry #> <string>"
		" - Synchronize entries using the secret key from the specified file and the speficied\n"
		"   public key of a remote peer. Add or update the entry with the specified id with\n"
		"   the specified value.\n"
		"put <string>                   - Store the given string in the DHT as an offline message\n"
		"get <hash>                     - get the message with the given hash\n";
	exit(1);
}

secret_key load_key_from_file(std::string const& filename)
{
	std::FILE* keyfile = std::fopen(filename.c_str(), "rb+");
	if (keyfile == nullptr)
	{
		std::cerr << "Failed to open key file" << std::endl;
		throw std::system_error(std::error_code(errno
			, std::system_category()));
	}
	scout::secret_key sk;
	size_t read = std::fread(sk.data(), 1, sk.size(), keyfile);
	std::fclose(keyfile);
	if (read != sk.size())
	{
		std::cerr << "Failed to read key file" << std::endl;
		if (std::feof(keyfile))
		{
			throw std::runtime_error("file too short");
		}
		else
		{
			throw std::system_error(std::error_code(ferror(keyfile)
				, std::system_category()));
		}
	}
	return sk;
}

int main(int argc, char const* argv[])
{
	// skip path to self
	++argv;
	--argc;
	if (argc < 1) usage();

	if (strcmp(argv[0], "gen-key") == 0)
	{
		++argv;
		--argc;
		if (argc < 1) usage();

		auto key = scout::generate_keypair();
		std::FILE* keyfile = std::fopen(argv[0], "wb+");
		if (keyfile == nullptr)
		{
			std::cerr << "Failed to open key file" << std::endl;
			return 1;
		}
		size_t written = std::fwrite(key.first.data(), 1, key.first.size(), keyfile);
		if (written != key.first.size())
		{
			std::cerr << "Failed to write key to file" << std::endl;
			std::fclose(keyfile);
			return 1;
		}
		std::fclose(keyfile);

		return 0;
	}

	if (strcmp(argv[0], "dump-key") == 0)
	{
		++argv;
		--argc;
		if (argc < 1) usage();

		scout::secret_key sk;
		try {
			sk = load_key_from_file(argv[0]);
		}
		catch (std::exception const& e) {
			std::cerr << "Failed to load key from file. You must generate a key first using "
				"the gen-key command\n";
			return 1;
		}
		scout::public_key pk;
		crypto_scalarmult_base((unsigned char*)pk.data()
			, (unsigned char*)sk.data());
		std::cout << "Public key: " << base16_encode({ (char*)pk.data(), pk.size() }) << std::endl;
		return 0;
	}

	scout::dht_session ses;
	ses.start();

	std::condition_variable op_complete;

	if (strcmp(argv[0], "sync") == 0)
	{
		++argv;
		--argc;
		if (argc < 4) usage();

		scout::secret_key sk;
		try {
			sk = load_key_from_file(argv[0]);
		} catch (std::exception const& e) {
			std::cerr << "Failed to load key from file. You must generate a key first using "
				"the gen-key command\n";
			return 1;
		}
		std::string pk_str = base16_decode(argv[1]);
		scout::public_key pk;
		if (pk_str.size() != pk.size()) usage();
		std::memcpy(pk.data(), pk_str.data(), pk.size());
		scout::secret_key shared_secret = scout::key_exchange(sk, pk);
		std::uint32_t eid = std::uint32_t(std::stoul(argv[2]));
		scout::entry e(eid);
		std::vector<gsl::byte> content((gsl::byte const*)argv[3]
			, (gsl::byte const*)argv[3] + std::strlen(argv[3]));
		e.assign(content);
		std::vector<scout::entry> entries;
		entries.push_back(e);
		ses.synchronize(shared_secret, std::move(entries)
			, [](entry const&) {}
			, [=](std::vector<entry>& entries)
			{
				for (entry& e : entries)
				{
					if (e.id() == eid && e.value() != content)
						e.assign(content);
					std::cout << e.id() << ' ' << std::string(e.value().begin(), e.value().end())
						<< '\n';
				}
			}
			, [&]() { op_complete.notify_all(); });
	}

	if (strcmp(argv[0], "put") == 0)
	{
		++argv;
		--argc;
		if (argc < 1) usage();

		scout::list_head head;
		gsl::span<gsl::byte const> contents((gsl::byte const*)argv[0]
			, (gsl::byte const*)argv[0] + std::strlen(argv[0]));
		scout::list_token token = head.push_front(contents);
		ses.put(token, contents, [&]() { op_complete.notify_all(); });
		std::cout << "inserted message with hash "
			<< base16_encode({ (char const *)head.head().data()
				, head.head().size() }) << std::endl;
	}
	else if (strcmp(argv[0], "get") == 0)
	{
		++argv;
		--argc;
		if (argc < 1) usage();

		std::string addr_str = base16_decode(argv[0]);
		scout::hash address;
		if (addr_str.size() != address.size()) usage();
		std::memcpy(address.data(), addr_str.data(), addr_str.size());
		ses.get(address, [&](std::vector<gsl::byte> contents, hash const& next_hash)
		{
			std::cout << "Got message: " << std::string((char*)contents.data(), contents.size()) << "\n"
				<< "Next hash: " << base16_encode({ (char*)next_hash.data(), next_hash.size() }) << "\n";
			op_complete.notify_all();
		});
	}

	std::mutex m;
	std::unique_lock<std::mutex> l(m);
	op_complete.wait(l);
}
