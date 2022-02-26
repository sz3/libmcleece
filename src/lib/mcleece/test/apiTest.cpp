/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#include "unittest.h"
#include "TestHelpers.h"

#include "mcleece/mcleece.h"

#include <string>
#include <vector>

using std::string;

TEST_CASE( "apiTest/testRoundtrip", "[unit]" )
{
	std::vector<unsigned char> pubk;
	pubk.resize(mcleece_simple_PUBLIC_KEY_SIZE);

	std::vector<unsigned char> secret;
	secret.resize(mcleece_simple_SECRET_KEY_SIZE);

	{
		int res = mcleece_simple_keypair(pubk.data(), secret.data());
		assertEquals( 0, res );
	}

	string srcMessage = "hello friends";
	std::vector<unsigned char> cipherText;
	cipherText.resize(srcMessage.size() + mcleece_simple_MESSAGE_HEADER_SIZE);
	{
		int res = mcleece_simple_encrypt(cipherText.data(), reinterpret_cast<unsigned char*>(srcMessage.data()), srcMessage.size(), pubk.data());
		assertEquals( 0, res );
	}

	string dstMessage;
	dstMessage.resize(srcMessage.size());
	{
		int res = mcleece_simple_decrypt(reinterpret_cast<unsigned char*>(dstMessage.data()), cipherText.data(), cipherText.size(), secret.data());
		assertEquals(0, res);
	}

	assertEquals( "hello friends", dstMessage );
}

