/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#include "unittest.h"
#include "TestHelpers.h"

#include "mcleece/message.h"
#include "mcleece/simple.h"

#include "util/MakeTempDirectory.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

using std::string;
using namespace std;


TEST_CASE( "simpleTest/testDecrypt", "[unit]" )
{
	MakeTempDirectory tempdir;

	TestHelpers::generate_keypair(tempdir.path() / "test");
	mcleece::public_key pubk = mcleece::public_key_simple::from_file(tempdir.path() / "test.pk");
	mcleece::private_key secret = mcleece::private_key_simple::from_file(tempdir.path() / "test.sk", "password");

	mcleece::session_key session = mcleece::keygen::generate_session_key(pubk);
	mcleece::nonce n;
	std::string sessiontext = mcleece::message::encode_session(session, n);
	std::string ciphertext = mcleece::message::encrypt("hello world", session, n);

	ciphertext = sessiontext + ciphertext;
	std::string decryptBuff;
	decryptBuff.resize(ciphertext.size() - mcleece::simple::MESSAGE_HEADER_SIZE);
	assertEquals( 11, decryptBuff.size() );

	assertEquals( 0, mcleece::simple::decrypt(decryptBuff, ciphertext, secret) );
	assertEquals( "hello world", decryptBuff );
}

TEST_CASE( "simpleTest/testEncrypt", "[unit]" )
{
	MakeTempDirectory tempdir;

	TestHelpers::generate_keypair(tempdir.path() / "test");
	mcleece::public_key pubk = mcleece::public_key_simple::from_file(tempdir.path() / "test.pk");
	mcleece::private_key secret = mcleece::private_key_simple::from_file(tempdir.path() / "test.sk", "password");

	std::string startBuff = "hello friends";
	std::string encryptedBuff;
	encryptedBuff.resize(startBuff.size() + mcleece::simple::MESSAGE_HEADER_SIZE);

	assertEquals( 0, mcleece::simple::encrypt(encryptedBuff, startBuff, pubk) );

	auto session_nonce = mcleece::message::decode_session(encryptedBuff, secret);
	assertTrue( session_nonce );

	mcleece::session_key& enc_session = session_nonce->first;
	mcleece::nonce& enc_n = session_nonce->second;

	std::string ciphertext = encryptedBuff.substr(mcleece::message::session_header_size());
	std::string message = mcleece::message::decrypt(ciphertext, enc_session, enc_n);
	assertEquals( "hello friends", message );
}

TEST_CASE( "simpleTest/testRoundtrip", "[unit]" )
{
	MakeTempDirectory tempdir;

	TestHelpers::generate_keypair(tempdir.path() / "test");
	mcleece::public_key pubk = mcleece::public_key_simple::from_file(tempdir.path() / "test.pk");
	mcleece::private_key secret = mcleece::private_key_simple::from_file(tempdir.path() / "test.sk", "password");

	std::string startMsg = "hello friendos";
	std::string ciphertext;
	ciphertext.resize(startMsg.size() + mcleece::simple::MESSAGE_HEADER_SIZE);

	assertEquals( 0, mcleece::simple::encrypt(ciphertext, startMsg, pubk) );

	std::string endMsg;
	endMsg.resize(startMsg.size());

	assertEquals( 0, mcleece::simple::decrypt(endMsg, ciphertext, secret) );
	assertEquals( "hello friendos", endMsg );
}
