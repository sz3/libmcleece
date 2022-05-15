/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include "simple.h"
#include "sodium_crypto_box.h"
#include "serialize/format.h"
#include "util/byte_view.h"

#include "sodium/crypto_box.h"
#include <string>
#include <vector>

namespace mcleece {
namespace cbox {

	static const unsigned PUBLIC_KEY_SIZE = mcleece::public_key_cbox::size();
	static const unsigned SODIUM_PUBLIC_KEY_SIZE = mcleece::public_key_sodium::size();
	static const unsigned SECRET_KEY_SIZE = mcleece::private_key_cbox::size();
	static const unsigned MESSAGE_HEADER_SIZE = mcleece::session_key::size() + crypto_box_SEALBYTES;

	inline int crypto_box_keypair(public_key_cbox& pubk, private_key_cbox& secret)
	{
		if (::crypto_box_keypair(pubk.data(), secret.data()) != 0)
			return 69;

		mcleece::public_key_simple pk(pubk.data() + crypto_box_PUBLICKEYBYTES);
		mcleece::private_key_simple sk(secret.data() + crypto_box_SECRETKEYBYTES);
		if (mcleece::simple::keypair(pk, sk) != 0)
			return 70;

		return 0;
	}

	inline void mix_buf(unsigned char* out, const unsigned char* in, unsigned n)
	{
		for (unsigned i = 0; i < n; ++i)
			out[i] ^= in[i];
	}

	inline bool mcleece_seal_mix(mcleece::byte_view& out, unsigned char* key, const unsigned char* nonce, const mcleece::public_key_simple& pubk)
	{
		// generate and write (encrypted) McEliece session key to out
		mcleece::session_key session = mcleece::keygen::generate_session_key(pubk);
		out = {out.data(), out.size() + session.encrypted_key().size()};
		out.write(session.encrypted_key().data(), session.encrypted_key().size());

		// then mix key and session
		// currently: xor
		mix_buf(key, session.key().data(), session.key().size());

		return true;
	}

	inline bool mcleece_seal_open_mix(mcleece::byte_view& in, unsigned char* key, const unsigned char* nonce, const mcleece::private_key_simple& secret)
	{
		// read and decode (encrypted) McEliece session key from in
		if (in.size() < mcleece::session_key::size())
			return false;

		mcleece::byte_view session_bytes(in.data(), mcleece::session_key::size());
		mcleece::session_key session = mcleece::keygen::decode_session_key(session_bytes, secret);
		in.advance(mcleece::session_key::size());

		// then mix key and session
		// currently: xor
		mix_buf(key, session.key().data(), session.key().size());

		return true;
	}

	inline int crypto_box_seal(mcleece::byte_view output_c, const mcleece::byte_view message, const mcleece::public_key_cbox& pubk)
	{
		if (output_c.size() < message.size() + MESSAGE_HEADER_SIZE)
			return 65;

		mcleece::public_key_simple pks(pubk.data() + crypto_box_PUBLICKEYBYTES);
		auto mix = [&pks](mcleece::byte_view& out, unsigned char* key, const unsigned char* nonce)
		{
			return mcleece_seal_mix(out, key, nonce, pks);
		};

		mcleece::sodium_crypto_box box(pubk.data());
		box.mix(mix);
		return box.seal(const_cast<unsigned char*>(output_c.data()), message.data(), message.size());
	}

	inline int crypto_box_seal_open(mcleece::byte_view output_m, const mcleece::byte_view ciphertext, const mcleece::public_key_sodium& pubk, const mcleece::private_key_cbox& secret)
	{
		if (!pubk.good())
			return 64;

		if (ciphertext.size() < MESSAGE_HEADER_SIZE)
			return 65;

		mcleece::private_key_simple sk(secret.data() + crypto_box_SECRETKEYBYTES);
		auto mix = [&sk](mcleece::byte_view& in, unsigned char* key, const unsigned char* nonce)
		{
			return mcleece_seal_open_mix(in, key, nonce, sk);
		};

		mcleece::sodium_crypto_box box(pubk.data(), secret.data());
		box.mix(mix);
		return box.seal_open(const_cast<unsigned char*>(output_m.data()), ciphertext.data(), ciphertext.size());
	}
}}
