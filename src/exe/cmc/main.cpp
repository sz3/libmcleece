
extern "C" {
#include "mceliece348864/nist/rng.h"
}

#include "mcleese/public_key.h"
#include "mcleese/private_key.h"
#include "mcleese/mce.h"

#include "mceliece348864/crypto_kem.h"
#include <iostream>
#include <fstream>
#include <random>
#include <vector>
using std::vector;

namespace {
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

	int res = mcleese::generate_keypair("/tmp/test.pk", "/tmp/test.sk");
	std::cout << "hello" << res << std::endl;

	mcleese::public_key pubk("/tmp/test.pk");
	mcleese::private_key secret("/tmp/test.sk");

	// generate a session key (32 bytes) and its encrypted counterpart (128 bytes)
	vector<unsigned char> encrypted(crypto_kem_mceliece348864_ref_CIPHERTEXTBYTES);
	vector<unsigned char> key(crypto_kem_mceliece348864_ref_BYTES);
	crypto_kem_enc(encrypted.data(), key.data(), pubk.data());

	std::cout << " key is: " << std::endl;
	for (int i = 0; i < key.size(); ++i)
		std::cout << (unsigned)key[i] << std::endl;

	// decrypt the encrypted key
	vector<unsigned char> recoveredKey(crypto_kem_mceliece348864_ref_BYTES);
	crypto_kem_dec(recoveredKey.data(), encrypted.data(), secret.data());

	std::cout << "recovered key as: " << std::endl;
	for (int i = 0; i < recoveredKey.size(); ++i)
		std::cout << (unsigned)recoveredKey[i] << std::endl;

	return 0;
}
