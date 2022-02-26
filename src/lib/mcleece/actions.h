/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include "constants.h"
#include "keygen.h"
#include "message.h"

#include "serialize/format.h"
#include "util/byte_view.h"
#include <string>
#include <sstream>
#include <vector>

// return codes attempt to match https://www.freebsd.org/cgi/man.cgi?query=sysexits
// ... emphasis on "attempt". I think of it like picking from HTTP status codes...

// rename to mcleece::simple ???
// but keep the high-level actions here?? :hmm:
// or maybe put all the api stuff into a mcleece.hpp ...

namespace mcleece {
namespace actions {
	static const int MAX_MESSAGE_LENGTH = 0x100000;
	static const unsigned MESSAGE_HEADER_SIZE = mcleece::session_header_size() + crypto_secretbox_macbytes();

	inline int keypair(unsigned char* pubk, unsigned char* secret)
	{
		return mcleece::generate_keypair(pubk, secret);
	}

	inline int keypair_to_file(std::string keypath, std::string pw, int mode)
	{
		std::string pk = fmt::format("{}.pk", keypath);
		std::string sk = fmt::format("{}.sk", keypath);
		if (mode == SIMPLE)
			return mcleece::generate_keypair<SIMPLE>(pk, sk, pw);
		else // mode == CBOX
			return mcleece::generate_keypair<CBOX>(pk, sk, pw);
	}

	inline int encrypt(mcleece::byte_view output_c, mcleece::byte_view message, const unsigned char* pubk)
	{
		// generate session key. nonce initiallized to a random value, and incremented by 1 for every message
		// we only use multiple messages when the input is larger than the arbitrary MAX_LENGTH below
		mcleece::session_key session = mcleece::generate_session_key(pubk);
		mcleece::nonce n;

		// store session data first
		if (!mcleece::encode_session(output_c, session, n))
			return 66;
		if (!output_c.size())
			return 67;

		// it's all in RAM -- single chunk encode
		int res = mcleece::encrypt(output_c, message, session, n);
		if (res != 0)
			return 69 + res;

		return 0;
	}

	inline int decrypt(mcleece::byte_view output_m, mcleece::byte_view ciphertext, const unsigned char* secret)
	{
		// extract the session from the front of the input
		if (ciphertext.size() < mcleece::session_header_size())
			return 65;
		auto session_nonce = mcleece::decode_session(ciphertext, secret);
		if (!session_nonce)
			return 64;
		if (!ciphertext.advance(mcleece::session_header_size()))
			return 65;

		mcleece::session_key& enc_session = session_nonce->first;
		mcleece::nonce& enc_n = session_nonce->second;

		// extract the message bytes
		int res = mcleece::decrypt(output_m, ciphertext, enc_session, enc_n);
		if (res != 0)
			return 69 + res;

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

			std::string ciphertext = mcleece::encrypt(data, session, n);
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
		mcleece::public_key pubk = mcleece::public_key_simple::from_file(keypath);
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
		data.resize(mcleece::session_header_size());
		is.read(data.data(), data.size());
		last_read = is.gcount();

		if (!is or last_read < data.size())
			return 65;
		auto session_nonce = mcleece::decode_session(data, secret);
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
			std::string message = mcleece::decrypt(data, enc_session, enc_n);
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
