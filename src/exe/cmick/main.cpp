
extern "C" {
#include "mceliece348864/nist/rng.h"
}

#include "mceliece348864/crypto_kem.h"
#include <iostream>
#include <fstream>
#include <random>
#include <vector>
using std::vector;

namespace {
	void write(std::string filename, const vector<unsigned char>& contents)
	{
		std::ofstream of(filename);
		of.write(reinterpret_cast<const char*>(contents.data()), contents.size());
	}

	void init_rng()
	{
		// random_device offers poor randomness guarantees, unfortunately -- so it's not really a solution here.
		// but for the moment it will do
		std::random_device randomEngine;
		vector<unsigned char> seed(48, 0);
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

int main()
{
	init_rng();

	vector<unsigned char> pk(crypto_kem_mceliece348864_ref_PUBLICKEYBYTES);
	vector<unsigned char> sk(crypto_kem_mceliece348864_ref_SECRETKEYBYTES);
	int res = crypto_kem_keypair(pk.data(), sk.data());
	std::cout << "hello" << res << std::endl;

	write("/tmp/test.pk", pk);
	write("/tmp/test.sk", sk);


	return 0;
}
