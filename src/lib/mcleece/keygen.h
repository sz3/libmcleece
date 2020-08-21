/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include "public_key.h"
#include "private_key.h"
#include "session_key.h"

#include "mceliece8192128/crypto_kem.h"

namespace mcleece
{
	inline int generate_keypair(public_key& pubk, private_key& secret)
	{
		return crypto_kem_keypair(pubk.data(), secret.data());
	}

	inline int generate_keypair(std::string pubk_path, std::string secret_path)
	{
		public_key pubk;
		private_key secret;
		int res = generate_keypair(pubk, secret);
		if (res != 0)
			return res;

		pubk.save(pubk_path);
		secret.save(secret_path);
		return res;
	}

	// two ways to get a session_key
	// 1. generate a new one
	// 2. pass in a string? base64 encoded? ... maybe the encoding is up to session_key?
	inline session_key generate_session_key(const public_key& pubk)
	{
		session_key key;
		int res = crypto_kem_enc(key.encrypted_key_data(), key.key_data(), pubk.data());
		return key;
	}

	inline session_key decode_session_key(const private_key& secret, const std::vector<unsigned char>& encrypted_key)
	{
		session_key key(encrypted_key);
		int res = crypto_kem_dec(key.key_data(), key.encrypted_key_data(), secret.data());
		return key;
	}
}
