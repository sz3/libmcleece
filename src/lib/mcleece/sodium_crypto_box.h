/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include "sodium/crypto_box.h"

namespace mcleece {

class sodium_crypto_box
{
public:
	sodium_crypto_box(const unsigned char* pk, const unsigned char* sk=nullptr)
	    : _pk(pk)
	    , _sk(sk)
	{}

	int seal(unsigned char* c, const unsigned char* m, unsigned long long mlen)
	{
		return ::crypto_box_seal(c, m, mlen, _pk);
	}

	int seal_open(unsigned char* m, const unsigned char* c, unsigned long long clen)
	{
		if (_sk == nullptr)
			return 1;

		return ::crypto_box_seal_open(m, c, clen, _pk, _sk);
	}

protected:
	const unsigned char* _pk;
	const unsigned char* _sk;
};

}
