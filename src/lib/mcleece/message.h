#pragma once

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
	std::vector<unsigned char> encrypt(const session_key& session, const std::string& message, const nonce& n)
	{
		if (session.key().size() < crypto_secretbox_KEYBYTES)
			return std::vector<unsigned char>();

		std::vector<unsigned char> ciphertext(message.size() + crypto_secretbox_MACBYTES);
		int res = crypto_secretbox_easy(
			ciphertext.data(), reinterpret_cast<const unsigned char*>(message.data()), message.size(),
			n.data(), session.key().data()
		);
		if (res != 0)
			return std::vector<unsigned char>();
		return ciphertext;
	}

	std::string decrypt(const session_key& session, const std::vector<unsigned char>& ciphertext, const nonce& n)
	{
		if (session.key().size() < crypto_secretbox_KEYBYTES)
			return std::string();

		std::string message;
		message.resize(ciphertext.size() - crypto_secretbox_MACBYTES);
		int res = crypto_secretbox_open_easy(
			reinterpret_cast<unsigned char*>(&message[0]), ciphertext.data(), ciphertext.size(),
			n.data(), session.key().data()
		);
		if (res != 0)
			return std::string();
		return message;
	}

	std::string encode_session(const session_key& session, const nonce& n)
	{
		std::string buff;
		buff.resize(session.encrypted_key().size() + n.size());
		std::copy(session.encrypted_key().begin(), session.encrypted_key().end(), &buff[0]);
		std::copy(n.data(), n.data()+n.size(), &buff[session.encrypted_key().size()]);
		return base64::encode(buff);
	}

	std::optional<std::pair<session_key, nonce>> decode_session(const std::string& encoded)
	{
		std::string buff = base64::decode(encoded);
		if (buff.size() < session_key::SIZE + nonce::SIZE)
			return {};
		return {};
	}

	std::string encode(const std::vector<unsigned char>& ciphertext)
	{
		std::string buff(ciphertext.begin(), ciphertext.end());
		return base64::encode(buff);
	}

}
