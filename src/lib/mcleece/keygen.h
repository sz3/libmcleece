/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include "public_key.h"
#include "private_key.h"
#include "session_key.h"
#include "util/byte_view.h"

#include "mceliece6960119f/crypto_kem.h"

namespace mcleece
{
	// pubk must be at least public_key::size()
	// secret must be at least secret_key::size()
	inline int generate_keypair(unsigned char* pubk, unsigned char* secret)
	{
		return crypto_kem_keypair(pubk, secret);
	}

	template <int MODE>
	inline int generate_keypair(public_key<MODE>& pubk, private_key<MODE>& secret)
	{
		return generate_keypair(pubk.data_write(), secret.data_write());
	}

	template <int MODE>
	inline int generate_keypair(std::string pubk_path, std::string secret_path, std::string pw)
	{
		public_key<MODE> pubk;
		private_key<MODE> secret;
		int res = generate_keypair(pubk, secret);
		if (res != 0)
			return res;

		pubk.save(pubk_path);
		secret.save(secret_path, pw);
		return res;
	}

	inline session_key generate_session_key(const unsigned char* pubk)
	{
		session_key key;
		crypto_kem_enc(key.encrypted_key_data(), key.key_data(), pubk);
		return key;
	}

	template <int MODE>
	inline session_key generate_session_key(const public_key<MODE>& pubk)
	{
		return generate_session_key(pubk.data());
	}

	inline session_key decode_session_key(const mcleece::byte_view& encrypted_key, const unsigned char* secret)
	{
		session_key key(encrypted_key);
		crypto_kem_dec(key.key_data(), key.encrypted_key_data(), secret);
		return key;
	}

	template <int MODE>
	inline session_key decode_session_key(const mcleece::byte_view& encrypted_key, const private_key<MODE>& secret)
	{
		return decode_session_key(encrypted_key, secret.data());
	}
}
