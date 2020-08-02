
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

	mcleese::session_key session = mcleese::generate_session_key(pubk);

	std::cout << " key is: " << std::endl;
	for (int i = 0; i < session.key().size(); ++i)
		std::cout << (unsigned)session.key()[i] << std::endl;

	// decrypt the encrypted key
	mcleese::session_key recoveredSession = mcleese::decode_session_key(secret, session.encrypted_key());

	std::cout << "recovered key as: " << std::endl;
	for (int i = 0; i < recoveredSession.key().size(); ++i)
		std::cout << (unsigned)recoveredSession.key()[i] << std::endl;

	return 0;
}
