/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include "constants.h"
#include "util/byte_view.h"
#include "util/File.h"

#include "mceliece6960119f/crypto_kem.h"
#include "sodium/crypto_pwhash_scryptsalsa208sha256.h"
#include "sodium/randombytes.h"
#include <array>
#include <fstream>
#include <string>

namespace mcleece {

template <int MODE>
class private_key
{
public:
	static constexpr unsigned size()
	{
		if (MODE == SIMPLE)
			return SIMPLE_SECRET_KEY_SIZE;
		else
			return CBOX_SECRET_KEY_SIZE;
	}

protected:
	using DATA_ARRAY = std::array<unsigned char, size()>;
	using SALT_ARRAY = std::array<unsigned char, crypto_pwhash_scryptsalsa208sha256_SALTBYTES>;

protected:
	bool generate_scrypt_data(DATA_ARRAY& blob, const std::string& pw, const SALT_ARRAY& salt) const
	{
		return crypto_pwhash_scryptsalsa208sha256(blob.data(), blob.size(), pw.data(), pw.size(), salt.data(),
		                                          crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
		                                          crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) == 0;
	}


public:
	private_key()
	    : _view(static_cast<unsigned char*>(nullptr), 0)
	{}

	explicit private_key(const unsigned char* buff)
	    : _view(buff, size())
	{}

	static private_key from_file(std::string filename, std::string pw)
	{
		private_key sk;
		if (!sk.load(filename, pw))
			sk._good = false;
		return sk;
	}

	bool good() const
	{
		return _good;
	}

	unsigned char* data()
	{
		if (_view.size())
			return const_cast<unsigned char*>(_view.data());
		else
			return _data.data();
	}

	const unsigned char* data() const
	{
		if (_view.size())
			return _view.data();
		else
			return _data.data();
	}

	bool save(const std::string& filename, const std::string& pw) const
	{
		// random salt
		SALT_ARRAY salt;
		randombytes(salt.data(), salt.size());

		// scrypt a data stream of N bytes
		DATA_ARRAY blob;
		if (!generate_scrypt_data(blob, pw, salt))
			return false;

		// xor our underlying data into it
		for (unsigned i = 0; i < blob.size(); ++i)
			blob[i] ^= _data[i];

		File f(filename, true, 0600);
		f.write(reinterpret_cast<const char*>(salt.data()), salt.size());
		f.write(reinterpret_cast<const char*>(blob.data()), blob.size());
		return true;
	}

	bool load(const std::string& filename, const std::string& pw)
	{
		std::ifstream f(filename, std::ios::binary);

		// load salt
		SALT_ARRAY salt;
		f.read(reinterpret_cast<char*>(salt.data()), salt.size());

		// load data blob
		f.read(reinterpret_cast<char*>(_data.data()), _data.size());

		// using the salt and pw, re-derive our stream of N bytes
		DATA_ARRAY blob;
		if (!generate_scrypt_data(blob, pw, salt))
			return false;

		// xor it with the data blob to get our real data back
		for (unsigned i = 0; i < _data.size(); ++i)
			_data[i] ^= blob[i];
		return true;
	}

protected:
	const mcleece::byte_view _view;
	DATA_ARRAY _data;
	bool _good = true;
};

using private_key_simple = private_key<SIMPLE>;
using private_key_cbox = private_key<CBOX>;

}
