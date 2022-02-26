/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include "actions.h"
#include "serialize/format.h"
#include "util/byte_view.h"

#include "sodium/crypto_box.h"
#include <string>
#include <vector>

// rename to mcleece::cbox ???

namespace mcleece {
namespace easy {

	static const unsigned PUBLIC_KEY_SIZE = mcleece::public_key_cbox::size();
	static const unsigned SECRET_KEY_SIZE = mcleece::private_key::size() + crypto_box_SECRETKEYBYTES;
	static const unsigned FULL_MESSAGE_HEADER_SIZE = mcleece::actions::MESSAGE_HEADER_SIZE + crypto_box_SEALBYTES;

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
		if (output_c.size() < message.size() + FULL_MESSAGE_HEADER_SIZE)
			return 65;

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
		if (ciphertext.size() < FULL_MESSAGE_HEADER_SIZE)
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

	// `message` should be plaintext sized to len(message) + MESSAGE_HEADER_SIZE
	inline int inplace_crypto_box_seal(mcleece::byte_view& message, mcleece::byte_view& scratch, const unsigned char* pubk)
	{
		// message contains the data going on, and will be overwritten with the final ciphertext.
		// scratch will hold the intermediate representation -- a normal libsodium crypto_box_seal result
		// inner layer: crypto_box. outer layer: libmcleece encrypt
		if (message.size() < FULL_MESSAGE_HEADER_SIZE)
			return 65;
		if (scratch.size() < message.size() - mcleece::actions::MESSAGE_HEADER_SIZE)
			return 66;

		mcleece::byte_view input(message.data(), message.size() - FULL_MESSAGE_HEADER_SIZE);
		int res = ::crypto_box_seal(const_cast<unsigned char*>(scratch.data()), input.data(), input.size(), pubk);
		if (res != 0)
			return 69;

		pubk += crypto_box_PUBLICKEYBYTES;

		mcleece::byte_view ciphertext = message;
		res = mcleece::actions::encrypt(ciphertext, scratch, pubk);
		if (res != 0)
			return 69 + res;

		return 0;
	}

	inline int inplace_crypto_box_seal_open(mcleece::byte_view& message, mcleece::byte_view& scratch, const unsigned char* pubk, const unsigned char* secret)
	{
		if (message.size() < FULL_MESSAGE_HEADER_SIZE)
			return 65;
		if (scratch.size() < crypto_box_SEALBYTES)
			return 66;

		int res = mcleece::actions::decrypt(scratch, message, secret + crypto_box_SECRETKEYBYTES);
		if (res != 0)
			return 69 + res;

		res = ::crypto_box_seal_open(const_cast<unsigned char*>(message.data()), scratch.data(), scratch.size(), pubk, secret);
		if (res != 0)
			return 69;

		message = {message.data(), message.size() - FULL_MESSAGE_HEADER_SIZE};
		return 0;
	}
}}
