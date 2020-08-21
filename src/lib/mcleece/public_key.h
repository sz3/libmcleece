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
	public_key()
	    : _data(crypto_kem_PUBLICKEYBYTES)
	{}

	public_key(std::string filename)
	    : public_key()
	{
		load(filename);
	}

	unsigned char* data()
	{
		return _data.data();
	}

	const unsigned char* data() const
	{
		return _data.data();
	}

	unsigned size() const
	{
		return _data.size();
	}

	bool save(const std::string& filename) const
	{
		std::ofstream f(filename, std::ios::binary);
		f.write(reinterpret_cast<const char*>(_data.data()), _data.size());
	}

	bool load(const std::string& filename)
	{
		std::ifstream f(filename, std::ios::binary);
		f.read(reinterpret_cast<char*>(_data.data()), _data.size());
	}

protected:
	std::vector<unsigned char> _data;
};

}
