/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#include "unittest.h"

#include "mcleece/actions.h"
#include "mcleece/message.h"

#include "util/MakeTempDirectory.h"

#include "PicoSHA2/picosha2.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

using std::string;
using namespace std;

namespace {
	std::string get_hash(std::string filename)
	{
		std::ifstream f(filename, std::ios::binary);
		std::vector<unsigned char> hash(picosha2::k_digest_size);
		picosha2::hash256(f, hash.begin(), hash.end());
		return picosha2::bytes_to_hex_string(hash);
	}
}

TEST_CASE( "actionsTest/testDecrypt", "[unit]" )
{
	MakeTempDirectory tempdir;

	TestHelpers::generate_keypair(tempdir.path() / "test");
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
	assertEquals(0, mcleece::actions::decrypt(tempdir.path() / "test.sk", "password", std::ifstream(tempdir.path() / "encrypted_msg"), ss));
	assertEquals( "hello world", ss.str() );
}

TEST_CASE( "messageTest/testEncrypt", "[unit]" )
{
	MakeTempDirectory tempdir;

	TestHelpers::generate_keypair(tempdir.path() / "test");
	mcleece::private_key secret(tempdir.path() / "test.sk", "password");

	{
		std::ofstream f(tempdir.path() / "helloworld");
		f << "hello friends";
	}

	std::stringstream ss;
	assertEquals( 0, mcleece::actions::encrypt(tempdir.path() / "test.pk", std::ifstream(tempdir.path() / "helloworld"), ss) );

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

	TestHelpers::generate_keypair(tempdir.path() / "test");

	{
		std::ofstream f(tempdir.path() / "helloworld");
		f << "hello friends";
	}

	{
		std::ofstream f(tempdir.path() / "encrypted_msg");
		assertEquals( 0, mcleece::actions::encrypt(tempdir.path() / "test.pk", std::ifstream(tempdir.path() / "helloworld"), f) );
	}

	std::stringstream ss;
	assertEquals(0, mcleece::actions::decrypt(tempdir.path() / "test.sk", "password", std::ifstream(tempdir.path() / "encrypted_msg"), ss));
	assertEquals( "hello friends", ss.str() );
}

TEST_CASE( "actionsTest/testRoundtrip.BigFile", "[unit]" )
{
	MakeTempDirectory tempdir;

	TestHelpers::generate_keypair(tempdir.path() / "test");

	{
		std::ofstream f(tempdir.path() / "bigfile");
		const unsigned size = 10000000;
		for (unsigned i = 0; i < size; i+=10)
			f << "0123456789";
	}

	{
		std::ofstream f(tempdir.path() / "encrypted_msg");
		assertEquals( 0, mcleece::actions::encrypt(tempdir.path() / "test.pk", std::ifstream(tempdir.path() / "bigfile"), f) );
	}

	{
		std::ofstream f(tempdir.path() / "decrypted");
		assertEquals( 0, mcleece::actions::decrypt(tempdir.path() / "test.sk", "password", std::ifstream(tempdir.path() / "encrypted_msg"), f) );
	}

	string actual = get_hash(tempdir.path() / "decrypted");
	assertEquals("d52fcc26b48dbd4d79b125eb0a29b803ade07613c67ac7c6f2751aefef008486", actual);
}


