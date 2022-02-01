/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include "mceliece8192128/crypto_kem.h"
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace mcleece {

class public_key
{
public:
	static constexpr unsigned size()
	{
		return crypto_kem_PUBLICKEYBYTES;
	}

public:
	public_key()
	    : _data(size())
	{}

	public_key(const unsigned char* data)
	    : _data(size())
	{
		std::copy(data, data+size(), &_data[0]);
	}

	static public_key from_file(std::string filename)
	{
		public_key pk;
		pk.load(filename);
		return pk;
	}

	unsigned char* data()
	{
		return _data.data();
	}

	const unsigned char* data() const
	{
		return _data.data();
	}

	bool save(const std::string& filename) const
	{
		std::ofstream f(filename, std::ios::binary);
		f.write(reinterpret_cast<const char*>(_data.data()), _data.size());
		return true;
	}

	bool load(const std::string& filename)
	{
		std::ifstream f(filename, std::ios::binary);
		f.read(reinterpret_cast<char*>(_data.data()), _data.size());
		return true;
	}

protected:
	std::vector<unsigned char> _data;
};

}
