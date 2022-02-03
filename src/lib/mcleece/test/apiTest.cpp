/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#include "unittest.h"

#include "mcleece/mcleece.h"

#include <string>
#include <vector>

using std::string;

TEST_CASE( "apiTest/testRoundtrip", "[unit]" )
{
	std::vector<unsigned char> pubk;
	pubk.resize(mcleece_public_key_size());

	std::vector<unsigned char> secret;
	secret.resize(mcleece_secret_key_size());

	{
		int res = mcleece_keypair(pubk.data(), secret.data());
		assertEquals( 0, res );
	}

	string srcMessage = "hello friends";
	std::vector<unsigned char> cipherText;
	cipherText.resize(srcMessage.size() + mcleece_message_header_size());
	{
		int res = mcleece_encrypt(cipherText.data(), reinterpret_cast<unsigned char*>(srcMessage.data()), srcMessage.size(), pubk.data());
		assertEquals( 0, res );
	}

	string dstMessage;
	dstMessage.resize(srcMessage.size());
	{
		int res = mcleece_decrypt(reinterpret_cast<unsigned char*>(dstMessage.data()), cipherText.data(), cipherText.size(), secret.data());
		assertEquals(0, res);
	}

	assertEquals( "hello friends", dstMessage );
}

