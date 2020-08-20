/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

extern "C" {
#include "mceliece348864/nist/rng.h"
}

#include <random>
#include <vector>

namespace mcleece
{
	void init_rng()
	{
		// random_device offers poor randomness guarantees, unfortunately -- so it's not really a solution here.
		// but for the moment it will do
		std::random_device randomEngine;
		std::vector<unsigned char> seed(48, 0);
		for (int count = 0; count < seed.size();)
		{
			unsigned rng = randomEngine();
			for (int i = 0; i < sizeof(unsigned) and count < seed.size(); ++i, ++count)
			{
				seed[count] = rng & 0xFF;
				rng = rng >> 8;
			}
		}
		randombytes_init(seed.data(), NULL, 0);
	}
}
