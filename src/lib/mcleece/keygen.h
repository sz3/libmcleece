/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include "public_key.h"
#include "private_key.h"
#include "session_key.h"

#include "mceliece8192128/crypto_kem.h"

namespace mcleece
{
	// pubk must be at least public_key::size()
	// secret must be at least secret_key::size()
	inline int generate_keypair(unsigned char* pubk, unsigned char* secret)
	{
		return crypto_kem_keypair(pubk, secret);
	}

	inline int generate_keypair(public_key& pubk, private_key& secret)
	{
		return generate_keypair(pubk.data(), secret.data());
	}

	inline int generate_keypair(std::string pubk_path, std::string secret_path, std::string pw)
	{
		public_key pubk;
		private_key secret;
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

	inline session_key generate_session_key(const public_key& pubk)
	{
		return generate_session_key(pubk.data());
	}

	inline session_key decode_session_key(const unsigned char* secret, const std::vector<unsigned char>& encrypted_key)
	{
		session_key key(encrypted_key);
		crypto_kem_dec(key.key_data(), key.encrypted_key_data(), secret);
		return key;
	}

	inline session_key decode_session_key(const private_key& secret, const std::vector<unsigned char>& encrypted_key)
	{
		return decode_session_key(secret.data(), encrypted_key);
	}
}
