
#include "mcleece/encrypt.h"
#include "mcleece/init_rng.h"
#include "mcleece/public_key.h"
#include "mcleece/private_key.h"
#include "mcleece/mce.h"

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
	mcleece::nonce n;
	vector<unsigned char> ciphertext = mcleece::encrypt(session, "hello world", n);

	std::string b64session = mcleece::encode_session(session, n);
	std::cout << b64session << std::endl;
	std::string b64c = mcleece::encode(ciphertext);
	std::cout << b64c << std::endl;

	// decrypt the encrypted key
	mcleece::session_key recoveredSession = mcleece::decode_session_key(secret, session.encrypted_key());
	std::string message = mcleece::decrypt(recoveredSession, ciphertext, n);

	std::cout << message << std::endl;
	return 0;
}
