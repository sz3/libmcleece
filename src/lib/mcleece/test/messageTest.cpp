/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#include "unittest.h"

#include "mcleece/keygen.h"
#include "mcleece/message.h"

#include "util/MakeTempDirectory.h"
#include <iostream>
#include <string>

using std::string;
using namespace std;


TEST_CASE( "messageTest/testRoundtrip", "[unit]" )
{
	MakeTempDirectory tempdir;

	mcleece::generate_keypair(tempdir.path() / "test.pk", tempdir.path() / "test.sk", "password");
	mcleece::public_key pubk(tempdir.path() / "test.pk");
	mcleece::private_key secret(tempdir.path() / "test.sk", "password");

	mcleece::session_key session = mcleece::generate_session_key(pubk);
	mcleece::nonce n;
	std::string ciphertext = mcleece::encrypt(session, "hello world", n);
	std::string sessiontext = mcleece::encode_session(session, n);

	auto session_nonce = mcleece::decode_session(secret, sessiontext);
	assertTrue( session_nonce );

	mcleece::session_key& enc_session = session_nonce->first;
	mcleece::nonce& enc_n = session_nonce->second;

	std::string message = mcleece::decrypt(enc_session, ciphertext, enc_n);
	assertEquals( "hello world", message );
}

