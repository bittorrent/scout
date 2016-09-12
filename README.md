# Overview

Scout is a library enabling two users to contact each other over the Internet using only their respective public keys. The Bittorrent distributed hash table (DHT) is used to store and retrieve contact information. Scout can also be used to store and retrieve short messages from the DHT so that peers can communicate even if they are never online at the same time.

# Prerequisites

Scout requires Boost 1.58 or newer and Libsodium 1.0 or newer

# Building

Scout uses Boost.Build version 2 to build. For information on installing BBv2 see the [Boost.Build manual](http://www.boost.org/build/doc/html/bbv2/installation.html). By default scout uses the versions of boost and libsodium which are installed on the system. If you are building on Windows you will need to specify the paths to the boost and libsodium source trees using the BOOST_ROOT and SODIUM_ROOT environment variables. Example commands to build scout on Windows:

    C:\scout> set BOOST_ROOT=C:\boost_1_60_0
    C:\scout> set SODIUM_ROOT=C:\libsodium-1.0.8
    C:\scout> bjam toolset=msvc-14

# Setting up a DHT session

Most users will want to use the dht_session class to easily set up a DHT node which can be used with the rest of scout's functions. To start a node create an instance of dht_session and call the start function.

	scout::dht_session ses;
	ses.start();

The start function will start a DHT node in a separate thread and return immediately. To stop the DHT node call the stop function.

	ses.stop();

This function will block until the dht node thread has exited. If stop is not called explicitly it will be called from the dht_session destructor.

# Generating a key pair

Scout provides the `generate_keypair` function to generate a new ed25519 key pair.

	std::pair<scout::secret_key, scout::public_key> keypair = scout::generate_keypair();

# Callbacks

The scout API involves many callback functions. When using the dht_session class it is important to keep in mind that callbacks will be invoked in the DHT node's thread rather than the main thread of your application. This means you need to be careful when accessing your application's data structures from a callback. Ideally callbacks will carry a copy of any data they might need to store in the DHT and post notifications to the main application event loop for new data retrieved from the DHT.

# Storage lifetime

Data stored in the DHT can only be expected to remain there for up to two hours. It is recommended that data be stored/synchronized roughly once an hour.

# Synchronizing contact information

Scout stores contact information as a vector of entries. Each entry must be assigned an id which is unique within that vector. The contents of the entries are left up to the application. Scout encrypts the entry vector before storing it in the DHT so applications do not need to encrypt each entry's contents.

To communicate entries between peers, scout uses a synchronize operation which retrieves the existing vector of entries from the DHT then writes a new vector with whatever updates the application specifies. To synchronize with a peer you need to have a shared secret to use as a key. Scout provides a key exchange function with uses Diffie-Hellman to generate a shared secret from the user's private key and a remote peer's public key.

	scout::secret_key shared_secret = scout::key_exchange(my_secret_key, remote_public_key);
	ses.synchronize(shared_secret, entries, entry_updated, finalize_entries, sync_finished);

The entries vector should contain the entries which the application is currently aware of. The `entry_updated` callback will be invoked when a new or updated entry is retrieved from the DHT. The `finalize_entries` callback will be invoked after all updates have been retrieved and before the updated entry vector is stored in the DHT, it provides the application a final opportunity to update the entries. The `sync_finished` callback is invoked once all store requests have completed, any resources associated with the operation may be freed by this function.

# Storing offline messages

Scout supports storing messages in the DHT so that a peer can retrieve them later even if the originator has gone offline. Messages are limited to 1000 bytes each. Scout does not encrypt message contents, the application is expected to have it's own message encryption scheme. Messages are stored in the DHT using the hash of their content as the key, thus the content of a message cannot be changed. A series of messages are stored as a linked list which can be retrieved using just the hash of the most recently stored message. Message lists are always retrieved in last-in-first-out order.

The first step is to create a message list.

	scout::list_head message_list;

You can then add one-or-more messages to the list.

	scout::list_token msg_token = message_list.push_front(message_contents);

The list_token contains the hash of the next message in the list, which corresponds to the previously added message. It should be stored alongside the message contents so that the message can be periodically stored in the DHT.

	ses.put(msg_token, message_contents, put_finished);

The msg_token must match the one returned from push_front for the given message. The storage backing the message contents must remain valid until the `put_finished` callback is invoked.

# Retrieving offline messages

To retrieve a list of offline messages you first must obtain the hash of the first message. The sender can get this hash from the `list_head`.

	hash head_hash = message_list.head();

Typically this hash will be included in the contents of an entry. Once the receiving peer has the hash it can retrieve the first message.

	ses.get(head_hash, message_received);

The `message_received` callback is passed the message contents along with the hash of the next message in the list.
