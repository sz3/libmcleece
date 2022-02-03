/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include "actions.h"
#include "serialize/format.h"
#include "util/byte_view.h"

#include "sodium/crypto_box.h"
#include <string>
#include <vector>

namespace mcleece {
namespace easy {

	static const unsigned PUBLIC_KEY_SIZE = mcleece::public_key::size() + crypto_box_PUBLICKEYBYTES;
	static const unsigned SECRET_KEY_SIZE = mcleece::private_key::size() + crypto_box_SECRETKEYBYTES;
	static const unsigned MESSAGE_HEADER_SIZE = mcleece::actions::MESSAGE_HEADER_SIZE + crypto_box_SEALBYTES;

	inline int crypto_box_keypair(unsigned char* pubk, unsigned char* secret)
	{
		if (::crypto_box_keypair(pubk, secret) != 0)
			return 69;

		pubk += crypto_box_PUBLICKEYBYTES;
		secret += crypto_box_SECRETKEYBYTES;
		if (mcleece::actions::keypair(pubk, secret) != 0)
			return 70;

		return 0;
	}

	inline int crypto_box_seal(mcleece::byte_view& output_c, mcleece::byte_view message, const unsigned char* pubk)
	{
		// inner layer: crypto_box. outer layer: libmcleece encrypt
		std::string scratch;
		scratch.resize(crypto_box_SEALBYTES + message.size());

		int res = ::crypto_box_seal(reinterpret_cast<unsigned char*>(scratch.data()), message.data(), message.size(), pubk);
		if (res != 0)
			return 69;

		pubk += crypto_box_PUBLICKEYBYTES;
		res = mcleece::actions::encrypt(output_c, mcleece::byte_view(scratch), pubk);
		if (res != 0)
			return 69 + res;

		return 0;
	}

	inline int crypto_box_seal_open(mcleece::byte_view& output_m, mcleece::byte_view ciphertext, const unsigned char* pubk, const unsigned char* secret)
	{
		if (ciphertext.size() < mcleece::actions::MESSAGE_HEADER_SIZE + crypto_box_SEALBYTES)
			return 65;

		std::string scratch;
		scratch.resize(ciphertext.size() - mcleece::actions::MESSAGE_HEADER_SIZE);

		mcleece::byte_view sb(scratch);
		int res = mcleece::actions::decrypt(sb, ciphertext, secret + crypto_box_SECRETKEYBYTES);
		if (res != 0)
			return 69 + res;

		res = ::crypto_box_seal_open(const_cast<unsigned char*>(output_m.data()), reinterpret_cast<unsigned char*>(scratch.data()), scratch.size(), pubk, secret);
		if (res != 0)
			return 69;

		return 0;
	}
}}
