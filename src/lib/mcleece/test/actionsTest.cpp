#include "unittest.h"

#include "mcleece/actions.h"

#include "mcleece/keygen.h"
#include "mcleece/message.h"

#include "util/File.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

using std::string;
using namespace std;


TEST_CASE( "actionsTest/testDecrypt", "[unit]" )
{
	// the best rng is no rng

	mcleece::generate_keypair("/tmp/test.pk", "/tmp/test.sk");
	mcleece::public_key pubk("/tmp/test.pk");

	mcleece::session_key session = mcleece::generate_session_key(pubk);
	mcleece::nonce n;
	std::string ciphertext = mcleece::encrypt(session, "hello world", n);
	std::string sessiontext = mcleece::encode_session(session, n);

	{
		std::ofstream f("/tmp/encrypted_msg");
		f << sessiontext;
		f << ciphertext;
	}

	std::stringstream ss;
	assertEquals(0, mcleece::actions::decrypt("/tmp/test.sk", "/tmp/encrypted_msg", ss));
	assertEquals( "hello world", ss.str() );
}

TEST_CASE( "messageTest/testEncrypt", "[unit]" )
{
	// the best rng is no rng

	mcleece::generate_keypair("/tmp/test.pk", "/tmp/test.sk");
	mcleece::private_key secret("/tmp/test.sk");

	{
		std::ofstream f("/tmp/helloworld");
		f << "hello friends";
	}

	std::stringstream ss;
	assertEquals( 0, mcleece::actions::encrypt("/tmp/test.pk", "/tmp/helloworld", ss) );

	std::string enc_message = ss.str();
	auto session_nonce = mcleece::decode_session(secret, enc_message);
	assertTrue( session_nonce );

	mcleece::session_key& enc_session = session_nonce->first;
	mcleece::nonce& enc_n = session_nonce->second;

	std::string ciphertext = enc_message.substr(mcleece::encoded_session_size());
	std::string message = mcleece::decrypt(enc_session, ciphertext, enc_n);
	assertEquals( "hello friends", message );
}


TEST_CASE( "actionsTest/testRoundtrip", "[unit]" )
{
	// the best rng is no rng
	mcleece::generate_keypair("/tmp/test.pk", "/tmp/test.sk");

	{
		std::ofstream f("/tmp/helloworld");
		f << "hello friends";
	}

	{
		std::ofstream f("/tmp/encrypted_msg");
		assertEquals( 0, mcleece::actions::encrypt("/tmp/test.pk", "/tmp/helloworld", f) );
	}

	std::stringstream ss;
	assertEquals(0, mcleece::actions::decrypt("/tmp/test.sk", "/tmp/encrypted_msg", ss));
	assertEquals( "hello friends", ss.str() );
}


