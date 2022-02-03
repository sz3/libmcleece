/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include "keygen.h"
#include "nonce.h"
#include "session_key.h"
#include "types.h"

#include "sodium/crypto_secretbox.h"
#include <iostream>
#include <optional>
#include <string>
#include <vector>
#include <utility>

namespace mcleece
{
	inline unsigned encrypt(const session_key& session, const mcleece::byte_view& message, const nonce& n, mcleece::byte_view ciphertext)
	{
		if (session.key().size() < crypto_secretbox_keybytes())
			return 0;

		size_t clen = message.size() + crypto_secretbox_macbytes();
		if (ciphertext.size() < clen)
			return 0;

		int res = crypto_secretbox_easy(
		    const_cast<unsigned char*>(ciphertext.data()), message.data(), message.size(),
		    n.data(), session.key().data()
		);
		if (res != 0)
			return 0;

		return clen;
	}

	inline std::string encrypt(const session_key& session, const std::string& message, const nonce& n)
	{
		std::string ciphertext;
		ciphertext.resize(message.size() + crypto_secretbox_macbytes());

		unsigned res = encrypt(session, message, n, ciphertext);
		if (!res)
			return std::string();
		return ciphertext;
	}

	inline unsigned decrypt(const session_key& session, const mcleece::byte_view& ciphertext, const nonce& n, mcleece::byte_view message)
	{
		if (session.key().size() < crypto_secretbox_keybytes())
			return 0;

		size_t mlen = ciphertext.size() - crypto_secretbox_macbytes();
		if (message.size() < mlen)
			return 0;

		unsigned res = crypto_secretbox_open_easy(
		    const_cast<unsigned char*>(message.data()), ciphertext.data(), ciphertext.size(),
		    n.data(), session.key().data()
		);
		if (res != 0)
			return 0;

		return mlen;
	}

	inline std::string decrypt(const session_key& session, const std::string& ciphertext, const nonce& n)
	{
		std::string message;
		message.resize(ciphertext.size() - crypto_secretbox_macbytes());

		unsigned res = decrypt(session, ciphertext, n, message);
		if (!res)
			return std::string();
		return message;
	}

	inline constexpr unsigned session_header_size()
	{
		return session_key::size() + nonce::size();
	}

	inline unsigned encode_session(const session_key& session, const nonce& n, mcleece::byte_view buff)
	{
		if (buff.size() < session.encrypted_key().size() + n.size())
			return 0;

		int count = buff.write(session.encrypted_key().data(), session.encrypted_key().size());
		count += buff.write(n.data(), n.size());
		return count;
	}

	inline std::string encode_session(const session_key& session, const nonce& n)
	{
		std::string buff;
		buff.resize(session.encrypted_key().size() + n.size());
		encode_session(session, n, buff);
		return buff;
	}

	inline std::optional<std::pair<session_key, nonce>> decode_session(const unsigned char* secret, mcleece::byte_view data)
	{
		if (data.size() < session_header_size())
			return {};

		mcleece::byte_view sbuff(data.data(), session_key::size());
		auto session = mcleece::decode_session_key(secret, sbuff);
		nonce n(data.data() + session_key::size());
		return {{session, n}};
	}

	inline std::optional<std::pair<session_key, nonce>> decode_session(const private_key& secret, mcleece::byte_view data)
	{
		return decode_session(secret.data(), data);
	}
}
