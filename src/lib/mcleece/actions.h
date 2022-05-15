/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include "cbox.h"
#include "constants.h"
#include "simple.h"

#include "serialize/format.h"
#include "util/byte_view.h"
#include <string>
#include <sstream>
#include <vector>

// return codes attempt to match https://www.freebsd.org/cgi/man.cgi?query=sysexits
// ... emphasis on "attempt". I think of it like picking from HTTP status codes...

namespace mcleece {
namespace actions {
	static const int MAX_MESSAGE_LENGTH = 0x100000;

	template <int MODE>
	inline int generate_keypair(std::string pubk_path, std::string secret_path, std::string pw)
	{
		public_key<MODE> pubk;
		private_key<MODE> secret;
		int res;
		if constexpr(MODE == SIMPLE)
			res = mcleece::simple::keypair(pubk, secret);
		else
			res = mcleece::cbox::crypto_box_keypair(pubk, secret);
		if (res != 0)
			return res;

		pubk.save(pubk_path);
		secret.save(secret_path, pw);
		return res;
	}

	inline int keypair_to_file(std::string keypath, std::string pw, int mode)
	{
		std::string pk = fmt::format("{}.pk", keypath);
		std::string sk = fmt::format("{}.sk", keypath);
		if (mode == SIMPLE)
			return generate_keypair<SIMPLE>(pk, sk, pw);
		else // mode == CBOX
			return generate_keypair<CBOX>(pk, sk, pw);
	}

	template <int MODE, typename INSTREAM, typename OUTSTREAM>
	int encrypt(const public_key<MODE>& pubk, INSTREAM&& is, OUTSTREAM& os, unsigned max_length=MAX_MESSAGE_LENGTH)
	{
		if (!is)
			return 66;

		const int header_length = (MODE == SIMPLE)? mcleece::simple::MESSAGE_HEADER_SIZE : mcleece::cbox::MESSAGE_HEADER_SIZE;

		std::string data;
		data.resize(max_length);
		std::string output;
		output.resize(max_length + header_length);

		// encrypt each chunk
		while (is)
		{
			is.read(data.data(), max_length);
			size_t last_read = is.gcount();
			if (last_read == 0)
				break;

			mcleece::byte_view dataview(data.data(), last_read);
			int res;
			if constexpr(MODE == SIMPLE)
				res = mcleece::simple::encrypt(output, dataview, pubk);
			else
				res = mcleece::cbox::crypto_box_seal(output, dataview, pubk);

			if (res)
				return res;

			std::string_view ciphertext = {output.data(), last_read + header_length};
			os << ciphertext;
		}
		return 0;
	}

	template <typename INSTREAM, typename OUTSTREAM>
	int encrypt(std::string keypath, INSTREAM&& is, OUTSTREAM& os, int mode, unsigned max_length=MAX_MESSAGE_LENGTH)
	{
		std::string pk = fmt::format("{}.pk", keypath);
		if (mode == SIMPLE)
		{
			mcleece::public_key pubk = mcleece::public_key_simple::from_file(pk);
			return encrypt(pubk, is, os, max_length);
		}
		else // mode == CBOX
		{
			mcleece::public_key pubk = mcleece::public_key_cbox::from_file(pk);
			return encrypt(pubk, is, os, max_length);
		}
	}

	template <int MODE, typename INSTREAM, typename OUTSTREAM>
	int decrypt(const public_key_sodium& pubk, const private_key<MODE>& secret, INSTREAM&& is, OUTSTREAM& os, unsigned max_length=MAX_MESSAGE_LENGTH)
	{
		if (!is)
			return 66;

		const int header_length = (MODE == SIMPLE)? mcleece::simple::MESSAGE_HEADER_SIZE : mcleece::cbox::MESSAGE_HEADER_SIZE;

		std::string data;
		data.resize(max_length + header_length);
		std::string output;
		output.resize(max_length);

		// extract the message bytes
		while (is)
		{
			is.read(data.data(), data.size());
			size_t last_read = is.gcount();
			if (last_read == 0)
				break;

			// decrypt the message
			mcleece::byte_view dataview(data.data(), last_read);
			int res;
			if constexpr(MODE == SIMPLE)
				res = mcleece::simple::decrypt(output, dataview, secret);
			else
				res = mcleece::cbox::crypto_box_seal_open(output, dataview, pubk, secret);

			if (res)
				return res;

			std::string_view plaintext = {output.data(), last_read - header_length};
			os << plaintext;
		}
		return 0;
	}

	template <typename INSTREAM, typename OUTSTREAM>
	int decrypt(const private_key_simple& secret, INSTREAM&& is, OUTSTREAM& os, unsigned max_length=MAX_MESSAGE_LENGTH)
	{
		return decrypt(public_key_sodium(nullptr), secret, is, os, max_length);
	}

	template <typename INSTREAM, typename OUTSTREAM>
	int decrypt(std::string keypath, std::string pw, INSTREAM&& is, OUTSTREAM& os, int mode, unsigned max_length=MAX_MESSAGE_LENGTH)
	{
		std::string pk = fmt::format("{}.pk", keypath);
		std::string sk = fmt::format("{}.sk", keypath);
		if (mode == SIMPLE)
		{
			mcleece::private_key secret = mcleece::private_key_simple::from_file(sk, pw);
			return decrypt(secret, is, os, max_length);
		}
		else // mode == CBOX
		{
			mcleece::private_key secret = mcleece::private_key_cbox::from_file(sk, pw);
			mcleece::public_key pubk = mcleece::public_key_sodium::from_file(pk);
			return decrypt(pubk, secret, is, os, max_length);
		}
	}
}}
