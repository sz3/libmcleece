/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include "util/byte_view.h"

#include "mceliece6960119f/crypto_kem.h"
#include "sodium/crypto_secretbox.h"
#include <array>
#include <string>
#include <vector>

static_assert(crypto_kem_BYTES == crypto_secretbox_KEYBYTES, "kem != secretbox keysize. Contemplate meaning of life");

namespace mcleece {

// this class currently serves two distinct purposes right now, which is interesting
// maybe a protected subclass with the "more public" methods? (and hiding the data accessors?)
class session_key
{
protected:
	static const int SIZE = crypto_kem_CIPHERTEXTBYTES;

public:
	using KEY_ARRAY = std::array<unsigned char, crypto_kem_BYTES>;
	using ENCRYPTED_ARRAY = std::array<unsigned char, SIZE>;

	static constexpr unsigned size()
	{
		return SIZE;
	}

public:
	session_key()
	    : _needsDecrypt(false)
	{
	}

	session_key(const mcleece::byte_view& encrypted_key)
	{
		_needsDecrypt = init_decode(encrypted_key);
	}

	bool init_decode(const mcleece::byte_view& encrypted_key)
	{
		if (encrypted_key.size() != _encryptedKey.size())
			return false;

		std::copy(encrypted_key.begin(), encrypted_key.end(), _encryptedKey.begin());
		return true;
	}

	bool needs_decrypt() const
	{
		return _needsDecrypt;
	}

	unsigned char* key_data()
	{
		return _key.data();
	}

	unsigned char* encrypted_key_data()
	{
		return _encryptedKey.data();
	}

	const KEY_ARRAY& key() const
	{
		return _key;
	}

	const ENCRYPTED_ARRAY& encrypted_key() const
	{
		return _encryptedKey;
	}

protected:
	bool _needsDecrypt;
	KEY_ARRAY _key;
	ENCRYPTED_ARRAY _encryptedKey;
};

}
