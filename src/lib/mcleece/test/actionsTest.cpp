/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#include "unittest.h"

#include "mcleece/actions.h"

#include "mcleece/keygen.h"
#include "mcleece/message.h"

#include "util/MakeTempDirectory.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

using std::string;
using namespace std;


TEST_CASE( "actionsTest/testDecrypt", "[unit]" )
{
	MakeTempDirectory tempdir;

	mcleece::generate_keypair(tempdir.path() / "test.pk", tempdir.path() / "test.sk", "password");
	mcleece::public_key pubk(tempdir.path() / "test.pk");

	mcleece::session_key session = mcleece::generate_session_key(pubk);
	mcleece::nonce n;
	std::string ciphertext = mcleece::encrypt(session, "hello world", n);
	std::string sessiontext = mcleece::encode_session(session, n);

	{
		std::ofstream f(tempdir.path() / "encrypted_msg");
		f << sessiontext;
		f << ciphertext;
	}

	std::stringstream ss;
	assertEquals(0, mcleece::actions::decrypt(tempdir.path() / "test.sk", "password", tempdir.path() / "encrypted_msg", ss));
	assertEquals( "hello world", ss.str() );
}

TEST_CASE( "messageTest/testEncrypt", "[unit]" )
{
	MakeTempDirectory tempdir;

	mcleece::generate_keypair(tempdir.path() / "test.pk", tempdir.path() / "test.sk", "password");
	mcleece::private_key secret(tempdir.path() / "test.sk", "password");

	{
		std::ofstream f(tempdir.path() / "helloworld");
		f << "hello friends";
	}

	std::stringstream ss;
	assertEquals( 0, mcleece::actions::encrypt(tempdir.path() / "test.pk", tempdir.path() / "helloworld", ss) );

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
	MakeTempDirectory tempdir;

	mcleece::generate_keypair(tempdir.path() / "test.pk", tempdir.path() / "test.sk", "password");

	{
		std::ofstream f(tempdir.path() / "helloworld");
		f << "hello friends";
	}

	{
		std::ofstream f(tempdir.path() / "encrypted_msg");
		assertEquals( 0, mcleece::actions::encrypt(tempdir.path() / "test.pk", tempdir.path() / "helloworld", f) );
	}

	std::stringstream ss;
	assertEquals(0, mcleece::actions::decrypt(tempdir.path() / "test.sk", "password", tempdir.path() / "encrypted_msg", ss));
	assertEquals( "hello friends", ss.str() );
}

