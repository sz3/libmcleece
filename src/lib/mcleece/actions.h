/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include "keygen.h"
#include "message.h"
#include "types.h"

#include "serialize/format.h"
#include <string>
#include <sstream>
#include <vector>

// return codes attempt to match https://www.freebsd.org/cgi/man.cgi?query=sysexits
// ... emphasis on "attempt". I think of it like picking from HTTP status codes...

namespace mcleece {
namespace actions {
	static const int MAX_MESSAGE_LENGTH = 0x100000;

	inline int keypair(unsigned char* pubk, unsigned char* secret)
	{
		return mcleece::generate_keypair(pubk, secret);
	}

	inline int keypair_to_file(std::string keypath, std::string pw)
	{
		return mcleece::generate_keypair(fmt::format("{}.pk", keypath), fmt::format("{}.sk", keypath), pw);
	}

	inline int encrypt(const unsigned char* pubk, mcleece::byte_view is, mcleece::byte_view& os)
	{
		// generate session key. nonce initiallized to a random value, and incremented by 1 for every message
		// we only use multiple messages when the input is larger than the arbitrary MAX_LENGTH below
		mcleece::session_key session = mcleece::generate_session_key(pubk);
		mcleece::nonce n;

		// store session data first
		std::optional<mcleece::byte_view> res = mcleece::encode_session(session, n, os);
		if (!res)
			return 66;
		os = *res;

		res = mcleece::encrypt(session, is, n, os);
		// it's all in RAM -- single chunk encode
		if (!res)
			return 70;
		os = *res;

		return 0;
	}

	inline int decrypt(const unsigned char* secret, mcleece::byte_view is, mcleece::byte_view& os)
	{
		// extract the session from the front of the input
		if (is.size() < mcleece::encoded_session_size())
			return 65;
		auto session_nonce = mcleece::decode_session(secret, mcleece::byte_view(is.data(), mcleece::encoded_session_size()));
		if (!session_nonce)
			return 64;
		if (!is.advance(mcleece::encoded_session_size()))
			return 65;

		mcleece::session_key& enc_session = session_nonce->first;
		mcleece::nonce& enc_n = session_nonce->second;

		// extract the message bytes
		if (!mcleece::decrypt(enc_session, is, enc_n, os))
			return 70;

		return 0;
	}

	template <typename INSTREAM, typename OUTSTREAM>
	int encrypt(const unsigned char* pubk, INSTREAM&& is, OUTSTREAM& os, unsigned max_length=MAX_MESSAGE_LENGTH)
	{
		if (!is)
			return 66;

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
			data.resize(max_length);
			is.read(data.data(), data.size());
			size_t last_read = is.gcount();

			if (last_read < data.size())
				data.resize(last_read);

			std::string ciphertext = mcleece::encrypt(session, data, n);
			if (ciphertext.empty())
				return 70;
			os << ciphertext;

			++n;
		}
		return 0;
	}

	template <typename INSTREAM, typename OUTSTREAM>
	int encrypt(std::string keypath, INSTREAM&& is, OUTSTREAM& os, unsigned max_length=MAX_MESSAGE_LENGTH)
	{
		mcleece::public_key pubk = mcleece::public_key::from_file(keypath);
		return encrypt(pubk.data(), is, os, max_length);
	}

	template <typename INSTREAM, typename OUTSTREAM>
	int decrypt(const unsigned char* secret, INSTREAM&& is, OUTSTREAM& os, unsigned max_length=MAX_MESSAGE_LENGTH)
	{
		if (!is)
			return 66;

		std::string data;
		size_t last_read;

		// extract the session from the front of the input
		data.resize(mcleece::encoded_session_size());
		is.read(data.data(), data.size());
		last_read = is.gcount();

		if (!is or last_read < data.size())
			return 65;
		auto session_nonce = mcleece::decode_session(secret, data);
		if (!session_nonce)
			return 64;

		mcleece::session_key& enc_session = session_nonce->first;
		mcleece::nonce& enc_n = session_nonce->second;

		// extract the message bytes
		const int MAX_CIPHERTEXT_LENGTH = max_length + crypto_secretbox_macbytes();
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
				return 70;
			os << message;

			++enc_n;
		}
		return 0;
	}

	template <typename INSTREAM, typename OUTSTREAM>
	int decrypt(std::string keypath, std::string pw, INSTREAM&& is, OUTSTREAM& os, unsigned max_length=MAX_MESSAGE_LENGTH)
	{
		mcleece::private_key secret = mcleece::private_key::from_file(keypath, pw);
		return decrypt(secret.data(), is, os, max_length);
	}
}}
