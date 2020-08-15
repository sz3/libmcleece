#pragma once

#include "keygen.h"
#include "nonce.h"
#include "session_key.h"

#include "base64/base.hpp"
#include "sodium/crypto_secretbox.h"
#include <iostream>
#include <optional>
#include <string>
#include <vector>
#include <utility>

namespace mcleece
{
	std::string encrypt(const session_key& session, const std::string& message, const nonce& n)
	{
		if (session.key().size() < crypto_secretbox_KEYBYTES)
			return std::string();

		std::string ciphertext;
		ciphertext.resize(message.size() + crypto_secretbox_MACBYTES);
		int res = crypto_secretbox_easy(
		    reinterpret_cast<unsigned char*>(&ciphertext[0]), reinterpret_cast<const unsigned char*>(message.data()), message.size(),
		    n.data(), session.key().data()
		);
		if (res != 0)
			return std::string();
		return ciphertext;
	}

	std::string decrypt(const session_key& session, const std::string& ciphertext, const nonce& n)
	{
		if (session.key().size() < crypto_secretbox_KEYBYTES)
			return std::string();

		std::string message;
		message.resize(ciphertext.size() - crypto_secretbox_MACBYTES);
		int res = crypto_secretbox_open_easy(
		    reinterpret_cast<unsigned char*>(&message[0]), reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size(),
		    n.data(), session.key().data()
		);
		if (res != 0)
			return std::string();
		return message;
	}

	constexpr unsigned encoded_session_size()
	{
		return session_key::SIZE + nonce::SIZE;
	}

	std::string encode_session(const session_key& session, const nonce& n)
	{
		std::string buff;
		buff.resize(session.encrypted_key().size() + n.size());
		std::copy(session.encrypted_key().begin(), session.encrypted_key().end(), &buff[0]);
		std::copy(n.data(), n.data()+n.size(), &buff[session.encrypted_key().size()]);
		return buff;
	}

	std::optional<std::pair<session_key, nonce>> decode_session(const private_key& secret, const char* data, unsigned len)
	{
		if (len < encoded_session_size())
			return {};

		std::vector<unsigned char> sbuff(data, data + session_key::SIZE);
		auto session = mcleece::decode_session_key(secret, sbuff);
		nonce n(data + session_key::SIZE);
		return {{session, n}};
	}

	std::optional<std::pair<std::vector<unsigned char>, nonce>> decode_session(const std::string& encoded)
	{
		// should move base64 stuff out of this file
		std::string buff = base64::decode(encoded);
		if (buff.size() < session_key::SIZE + nonce::SIZE)
			return {};

		std::vector<unsigned char> session(buff.data(), buff.data() + session_key::SIZE);
		nonce n(buff.data() + session_key::SIZE);
		return {{session, n}};
	}

	std::string encode(const std::vector<unsigned char>& ciphertext)
	{
		std::string buff(ciphertext.begin(), ciphertext.end());
		return base64::encode(buff);
	}

	std::vector<unsigned char> decode(const std::string& encoded_ciphertext)
	{
		std::string buff = base64::decode(encoded_ciphertext);
		return std::vector<unsigned char>(buff.begin(), buff.end());
	}

}
