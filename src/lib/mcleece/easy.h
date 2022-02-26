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
	static const unsigned SECRET_KEY_SIZE = mcleece::private_key_cbox::size();
	static const unsigned FULL_MESSAGE_HEADER_SIZE = mcleece::actions::MESSAGE_HEADER_SIZE + crypto_box_SEALBYTES;

	inline int crypto_box_keypair(public_key_cbox& pubk, private_key_cbox& secret)
	{
		if (::crypto_box_keypair(pubk.data(), secret.data()) != 0)
			return 69;

		mcleece::public_key_simple pk(pubk.data() + crypto_box_PUBLICKEYBYTES);
		mcleece::private_key_simple sk(secret.data() + crypto_box_SECRETKEYBYTES);
		if (mcleece::actions::keypair(pk, sk) != 0)
			return 70;

		return 0;
	}

	inline int crypto_box_seal(mcleece::byte_view& output_c, mcleece::byte_view message, const mcleece::public_key_cbox& pubk)
	{
		if (output_c.size() < message.size() + FULL_MESSAGE_HEADER_SIZE)
			return 65;

		// inner layer: crypto_box. outer layer: libmcleece encrypt
		std::string scratch;
		scratch.resize(crypto_box_SEALBYTES + message.size());

		int res = ::crypto_box_seal(reinterpret_cast<unsigned char*>(scratch.data()), message.data(), message.size(), pubk.data());
		if (res != 0)
			return 69;

		mcleece::public_key_simple pk(pubk.data() + crypto_box_PUBLICKEYBYTES);
		res = mcleece::actions::encrypt(output_c, mcleece::byte_view(scratch), pk);
		if (res != 0)
			return 69 + res;

		return 0;
	}

	inline int crypto_box_seal_open(mcleece::byte_view& output_m, mcleece::byte_view ciphertext, const mcleece::public_key_cbox& pubk, const mcleece::private_key_cbox& secret)
	{
		if (ciphertext.size() < FULL_MESSAGE_HEADER_SIZE)
			return 65;

		std::string scratch;
		scratch.resize(ciphertext.size() - mcleece::actions::MESSAGE_HEADER_SIZE);

		mcleece::byte_view sb(scratch);
		mcleece::private_key_simple sk(secret.data() + crypto_box_SECRETKEYBYTES);
		int res = mcleece::actions::decrypt(sb, ciphertext, sk);
		if (res != 0)
			return 69 + res;

		res = ::crypto_box_seal_open(const_cast<unsigned char*>(output_m.data()), reinterpret_cast<unsigned char*>(scratch.data()), scratch.size(), pubk.data(), secret.data());
		if (res != 0)
			return 69;

		return 0;
	}

	// `message` should be plaintext sized to len(message) + MESSAGE_HEADER_SIZE
	inline int inplace_crypto_box_seal(mcleece::byte_view& message, mcleece::byte_view& scratch, const mcleece::public_key_cbox& pubk)
	{
		// message contains the data going on, and will be overwritten with the final ciphertext.
		// scratch will hold the intermediate representation -- a normal libsodium crypto_box_seal result
		// inner layer: crypto_box. outer layer: libmcleece encrypt
		if (message.size() < FULL_MESSAGE_HEADER_SIZE)
			return 65;
		if (scratch.size() < message.size() - mcleece::actions::MESSAGE_HEADER_SIZE)
			return 66;

		mcleece::byte_view input(message.data(), message.size() - FULL_MESSAGE_HEADER_SIZE);
		int res = ::crypto_box_seal(const_cast<unsigned char*>(scratch.data()), input.data(), input.size(), pubk.data());
		if (res != 0)
			return 69;

		mcleece::byte_view ciphertext = message;
		mcleece::public_key_simple pk(pubk.data() + crypto_box_PUBLICKEYBYTES);
		res = mcleece::actions::encrypt(ciphertext, scratch, pk);
		if (res != 0)
			return 69 + res;

		return 0;
	}

	inline int inplace_crypto_box_seal_open(mcleece::byte_view& message, mcleece::byte_view& scratch, const mcleece::public_key_cbox& pubk, const mcleece::private_key_cbox& secret)
	{
		if (message.size() < FULL_MESSAGE_HEADER_SIZE)
			return 65;
		if (scratch.size() < crypto_box_SEALBYTES)
			return 66;

		mcleece::private_key_simple sk(secret.data() + crypto_box_SECRETKEYBYTES);
		int res = mcleece::actions::decrypt(scratch, message, sk);
		if (res != 0)
			return 69 + res;

		res = ::crypto_box_seal_open(const_cast<unsigned char*>(message.data()), scratch.data(), scratch.size(), pubk.data(), secret.data());
		if (res != 0)
			return 69;

		message = {message.data(), message.size() - FULL_MESSAGE_HEADER_SIZE};
		return 0;
	}
}}
