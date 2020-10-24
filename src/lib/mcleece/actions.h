/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include "keygen.h"
#include "message.h"

#include "serialize/format.h"
#include <string>
#include <sstream>
#include <vector>

namespace mcleece {
namespace actions {
	static const int MAX_MESSAGE_LENGTH = 0x100000;

	static int generate_keypair(std::string keypath, std::string pw)
	{
		int res = mcleece::generate_keypair(fmt::format("{}.pk", keypath), fmt::format("{}.sk", keypath), pw);
		return res;
	}

	template <typename INSTREAM, typename OUTSTREAM>
	int encrypt(std::string keypath, INSTREAM&& is, OUTSTREAM& os)
	{
		mcleece::public_key pubk(keypath);

		if (!is)
			return 104;

		// generate session key. nonce initiallized to a random value, and incremented by 1 for every message
		// we only use multiple messages when the input is larger than the arbitrary MAX_LENGTH below
		mcleece::session_key session = mcleece::generate_session_key(pubk);
		mcleece::nonce n;

		// store session data first
		std::string sessiontext = mcleece::encode_session(session, n);
		os << sessiontext;

		// encrypt each chunk
		std::string data;
		while (is)
		{
			data.resize(MAX_MESSAGE_LENGTH);
			is.read(data.data(), data.size());
			size_t last_read = is.gcount();

			if (last_read < data.size())
				data.resize(last_read);

			std::string ciphertext = mcleece::encrypt(session, data, n);
			if (ciphertext.empty())
				return 200;
			os << ciphertext;

			++n;
		}
		return 0;
	}

	template <typename INSTREAM, typename OUTSTREAM>
	int decrypt(std::string keypath, std::string pw, INSTREAM&& is, OUTSTREAM& os)
	{
		mcleece::private_key secret(keypath, pw);

		if (!is)
			return 104;

		std::string data;
		size_t last_read;

		// extract the session from the front of the input
		data.resize(mcleece::encoded_session_size());
		is.read(data.data(), data.size());
		last_read = is.gcount();

		if (!is or last_read < data.size())
			return 110;
		auto session_nonce = mcleece::decode_session(secret, data.data(), mcleece::encoded_session_size());
		if (!session_nonce)
			return 111;

		mcleece::session_key& enc_session = session_nonce->first;
		mcleece::nonce& enc_n = session_nonce->second;

		// extract the message bytes
		const int MAX_CIPHERTEXT_LENGTH = MAX_MESSAGE_LENGTH + crypto_secretbox_MACBYTES;
		while (is)
		{
			data.resize(MAX_CIPHERTEXT_LENGTH);
			is.read(data.data(), data.size());
			last_read = is.gcount();

			if (last_read < data.size())
				data.resize(last_read);

			// decrypt the message
			std::string message = mcleece::decrypt(enc_session, data, enc_n);
			if (message.empty())
				return 200;
			os << message;

			++enc_n;
		}
		return 0;
	}
}}
