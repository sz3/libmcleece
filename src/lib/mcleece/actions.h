/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include "keygen.h"
#include "message.h"

#include "base64/base.hpp"
#include "serialize/format.h"
#include <cstdio>
#include <string>
#include <sstream>
#include <vector>

namespace mcleece {
namespace actions {
	int generate_keypair(std::string keypath, std::string pw)
	{
		int res = mcleece::generate_keypair(fmt::format("{}.pk", keypath), fmt::format("{}.sk", keypath), pw);
		return res;
	}

	template <typename INSTREAM, typename OUTSTREAM>
	int encrypt(std::string keypath, INSTREAM&& is, OUTSTREAM& os)
	{
		mcleece::public_key pubk(keypath);

		std::string data;
		{
			std::stringstream ss;
			ss << is.rdbuf();
			data = ss.str();
		}
		if (data.empty())
			return 104;

		// limit is arbitrarily set at ~50MB. For files larger than that, chunk them up into multiple messages
		mcleece::session_key session = mcleece::generate_session_key(pubk);
		mcleece::nonce n;

		std::string ciphertext = mcleece::encrypt(session, data, n);
		if (ciphertext.empty())
			return 200;

		std::string sessiontext = mcleece::encode_session(session, n);
		os << sessiontext << ciphertext;
		return 0;
	}

	template <typename INSTREAM, typename OUTSTREAM>
	int decrypt(std::string keypath, std::string pw, INSTREAM&& is, OUTSTREAM& os)
	{
		mcleece::private_key secret(keypath, pw);

		std::string data;
		{
			std::stringstream ss;
			ss << is.rdbuf();
			data = ss.str();
		}
		if (data.empty())
			return 104;

		// extract the session from the front of the input
		if (data.size() < mcleece::encoded_session_size())
			return 110;
		auto session_nonce = mcleece::decode_session(secret, data.data(), mcleece::encoded_session_size());
		if (!session_nonce)
			return 111;

		mcleece::session_key& enc_session = session_nonce->first;
		mcleece::nonce& enc_n = session_nonce->second;

		// extract the message bytes
		std::string rec_ciphertext = data.substr(mcleece::encoded_session_size(), data.size());

		// decrypt the message
		std::string message = mcleece::decrypt(enc_session, rec_ciphertext, enc_n);
		if (message.empty())
			return 120;
		os << message;
		return 0;
	}
}}
