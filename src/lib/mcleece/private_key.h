/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include "mceliece6960119f/crypto_kem.h"
#include "util/File.h"

#include "sodium/crypto_pwhash_scryptsalsa208sha256.h"
#include "sodium/randombytes.h"
#include <array>
#include <fstream>
#include <string>

namespace mcleece {

class private_key
{
protected:
	static const int SIZE = crypto_kem_SECRETKEYBYTES;
	using DATA_ARRAY = std::array<unsigned char, SIZE>;
	using SALT_ARRAY = std::array<unsigned char, crypto_pwhash_scryptsalsa208sha256_SALTBYTES>;

protected:
	bool generate_scrypt_data(DATA_ARRAY& blob, const std::string& pw, const SALT_ARRAY& salt) const
	{
		return crypto_pwhash_scryptsalsa208sha256(blob.data(), blob.size(), pw.data(), pw.size(), salt.data(),
		                                          crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
		                                          crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) == 0;
	}

public:
	static constexpr unsigned size()
	{
		return SIZE;
	}

public:
	private_key()
	{}

	private_key(const unsigned char* buff)
	{
		std::copy(buff, buff+_data.size(), &_data[0]);
	}

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
		return _data.data();
	}

	const unsigned char* data() const
	{
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
	DATA_ARRAY _data;
	bool _good = true;
};

}
