#pragma once

extern "C" {
#include "mceliece348864/nist/rng.h"
}

#include "sodium/crypto_secretbox.h"
#include <vector>

namespace mcleece
{

class nonce
{
public:
	nonce(int size=0)
		: _data(size > 0? size : crypto_secretbox_NONCEBYTES)
	{
		randomize();
	}

	int randomize()
	{
		return randombytes(_data.data(), _data.size());
	}

	const unsigned char* data() const
	{
		return _data.data();
	}

	unsigned size() const
	{
		return _data.size();
	}

protected:
	std::vector<unsigned char> _data;
};

}
