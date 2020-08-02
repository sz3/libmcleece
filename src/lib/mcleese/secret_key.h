#pragma once

#include "mceliece348864/crypto_kem.h"
#include <fstream>
#include <string>
#include <vector>

namespace mcleese {

class secret_key
{
public:
	secret_key()
		: _sk(crypto_kem_SECRETKEYBYTES)
	{}

	unsigned char* sk()
	{
		return _sk.data();
	}

	unsigned size() const
	{
		return _sk.size();
	}

	bool save(const std::string& filename) const
	{
		// TODO: encrypt
		std::ofstream f(filename);
		f.write(reinterpret_cast<const char*>(_sk.data()), _sk.size());
	}

	bool load(const std::string& filename)
	{
		// TODO: decrypt
		std::ifstream f(filename, std::ios::binary);
		f.read(reinterpret_cast<char*>(_sk.data()), _sk.size());
	}

protected:
	std::vector<unsigned char> _sk;
};

}
