
#include "mcleece/init_rng.h"
#include "mcleece/public_key.h"
#include "mcleece/private_key.h"
#include "mcleece/mce.h"

#include "sodium/crypto_secretbox.h"
#include <iostream>
#include <fstream>
#include <random>
#include <vector>
using std::vector;

int main()
{
	mcleece::init_rng();

	int res = mcleece::generate_keypair("/tmp/test.pk", "/tmp/test.sk");
	std::cout << "hello" << res << std::endl;

	mcleece::public_key pubk("/tmp/test.pk");
	mcleece::private_key secret("/tmp/test.sk");

	mcleece::session_key session = mcleece::generate_session_key(pubk);

	std::cout << " key is: " << std::endl;
	for (int i = 0; i < session.key().size(); ++i)
		std::cout << (unsigned)session.key()[i] << std::endl;

	// decrypt the encrypted key
	mcleece::session_key recoveredSession = mcleece::decode_session_key(secret, session.encrypted_key());

	std::cout << "recovered key as: " << std::endl;
	for (int i = 0; i < recoveredSession.key().size(); ++i)
		std::cout << (unsigned)recoveredSession.key()[i] << std::endl;

	return 0;
}
