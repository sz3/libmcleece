#pragma once

#include "mceliece348864/crypto_kem.h"
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace mcleese {

class public_key
{
public:
	public_key()
		: _pk(crypto_kem_PUBLICKEYBYTES)
	{}

	unsigned char* pk()
	{
		return _pk.data();
	}

	unsigned size() const
	{
		return _pk.size();
	}

	bool save(const std::string& filename) const
	{
		std::ofstream f(filename, std::ios::binary);
		f.write(reinterpret_cast<const char*>(_pk.data()), _pk.size());
	}

	bool load(const std::string& filename)
	{
		std::ifstream f(filename, std::ios::binary);
		f.read(reinterpret_cast<char*>(_pk.data()), _pk.size());
	}

protected:
	std::vector<unsigned char> _pk;
};

}
