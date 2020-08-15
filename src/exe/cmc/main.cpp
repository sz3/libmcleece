
#include "mcleece/init_rng.h"
#include "mcleece/keygen.h"
#include "mcleece/message.h"
#include "mcleece/public_key.h"
#include "mcleece/private_key.h"

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
	std::string ciphertext = mcleece::encrypt(session, "hello world", n);

	std::string b64session = base64::encode(mcleece::encode_session(session, n));
	std::cout << b64session << std::endl;
	std::string b64c = base64::encode(ciphertext);
	std::cout << b64c << std::endl;

	std::string rec_session_data = base64::decode(b64session);
	auto session_nonce = mcleece::decode_session(secret, rec_session_data);
	if (!session_nonce)
		std::cout << "failed decode_session :(" << std::endl;

	mcleece::session_key& enc_session = session_nonce->first;
	mcleece::nonce& enc_n = session_nonce->second;
	std::string rec_ciphertext = base64::decode(b64c);

	// decrypt the encrypted key
	std::string message = mcleece::decrypt(enc_session, rec_ciphertext, enc_n);

	std::cout << message << std::endl;
	return 0;
}
