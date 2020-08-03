#pragma once

#include "base64/base.hpp"
#include "mceliece348864/crypto_kem.h"
#include <string>
#include <vector>

namespace mcleece {


// this class currently serves two distinct purposes right now, which is interesting
// maybe a protected subclass with the "more public" methods? (and hiding the data accessors?)
class session_key
{
public:
	session_key()
	    : _key(crypto_kem_BYTES)
	    , _encryptedKey(crypto_kem_CIPHERTEXTBYTES)
	    , _needsDecrypt(false)
	{
	}

	session_key(const std::vector<unsigned char>& encrypted_key)
	    : session_key()
	{
		init_decode(encrypted_key);
		_needsDecrypt = true;
	}

	bool init_decode(const std::vector<unsigned char>& encrypted_key)
	{
		if (encrypted_key.size() != _encryptedKey.size())
			return false;

		_encryptedKey = encrypted_key;
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

	const std::vector<unsigned char>& key() const
	{
		return _key;
	}

	const std::vector<unsigned char>& encrypted_key() const
	{
		return _encryptedKey;
	}

protected:
	bool _needsDecrypt;
	std::vector<unsigned char> _key;
	std::vector<unsigned char> _encryptedKey;
};

}
