/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include "public_key.h"
#include "private_key.h"
#include "session_key.h"
#include "util/byte_view.h"

#include "mceliece6960119f/crypto_kem.h"

namespace mcleece {
namespace keygen {

	// pubk must be at least public_key::size()
	// secret must be at least secret_key::size()
	inline int generate_keypair(public_key_simple& pubk, private_key_simple& secret)
	{
		return crypto_kem_keypair(pubk.data(), secret.data());
	}

	inline session_key generate_session_key(const public_key_simple& pubk)
	{
		session_key key;
		crypto_kem_enc(key.encrypted_key_data(), key.key_data(), pubk.data());
		return key;
	}

	inline session_key decode_session_key(const mcleece::byte_view& encrypted_key, const private_key_simple& secret)
	{
		session_key key(encrypted_key);
		crypto_kem_dec(key.key_data(), key.encrypted_key_data(), secret.data());
		return key;
	}
}}
