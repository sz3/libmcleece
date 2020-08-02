#pragma once

#include "mceliece348864/crypto_kem.h"
#include <fstream>
#include <string>
#include <vector>

namespace mcleese {

class private_key
{
public:
	private_key()
		: _data(crypto_kem_SECRETKEYBYTES)
	{}

	private_key(std::string filename)
		: private_key()
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
		// TODO: encrypt
		std::ofstream f(filename);
		f.write(reinterpret_cast<const char*>(_data.data()), _data.size());
	}

	bool load(const std::string& filename)
	{
		// TODO: decrypt
		std::ifstream f(filename, std::ios::binary);
		f.read(reinterpret_cast<char*>(_data.data()), _data.size());
	}

protected:
	std::vector<unsigned char> _data;
};

}
