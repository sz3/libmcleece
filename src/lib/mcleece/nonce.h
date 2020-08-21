/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

extern "C" {
#include "mceliece8192128/nist/rng.h"
}

#include "sodium/crypto_secretbox.h"
#include <vector>

namespace mcleece
{

class nonce
{
public:
	static const int SIZE = crypto_secretbox_NONCEBYTES;

public:
	nonce()
	    : _data(SIZE)
	{
		randomize();
	}

	nonce(const char* data)
	    : _data(SIZE)
	{
		std::copy(data, data+SIZE, _data.data());
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
