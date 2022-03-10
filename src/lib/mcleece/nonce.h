/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include "sodium/crypto_secretbox.h"
#include "sodium/randombytes.h"
#include <array>

namespace mcleece
{

class nonce
{
protected:
	static const int SIZE = crypto_secretbox_NONCEBYTES;

public:
	static constexpr unsigned size()
	{
		return SIZE;
	}

public:
	nonce()
	{
		randomize();
	}

	nonce(const unsigned char* data)
	{
		std::copy(data, data+size(), _data.data());
	}

	void randomize()
	{
		randombytes(_data.data(), _data.size());
	}

	const unsigned char* data() const
	{
		return _data.data();
	}

	nonce& operator++()
	{
		// could also do this by going <-> an int, but this is probably more straightforward?
		for (int i = _data.size()-1; i >= 0; --i)
		{
			unsigned char temp = _data[i];
			if (++_data[i] > temp)
				break; // if no overflow, we're done
			else if (i == 0)
				_data = {0};
		}
		return *this;
	}

protected:
	std::array<unsigned char, SIZE> _data;
};

}
