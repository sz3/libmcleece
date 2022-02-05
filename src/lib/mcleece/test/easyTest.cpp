/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#include "unittest.h"

#include "mcleece/mcleece.h"

#include <string>
#include <vector>

using std::string;

TEST_CASE( "easyTest/testRoundtrip", "[unit]" )
{
	std::vector<unsigned char> pubk;
	pubk.resize(mcleece_crypto_box_PUBLIC_KEY_SIZE);

	std::vector<unsigned char> secret;
	secret.resize(mcleece_crypto_box_SECRET_KEY_SIZE);

	{
		int res = mcleece_crypto_box_keypair(pubk.data(), secret.data());
		assertEquals( 0, res );
	}

	string srcMessage = "hello friends";
	std::vector<unsigned char> cipherText;
	cipherText.resize(srcMessage.size() + mcleece_crypto_box_MESSAGE_HEADER_SIZE);
	{
		int res = mcleece_crypto_box_seal(cipherText.data(), reinterpret_cast<unsigned char*>(srcMessage.data()), srcMessage.size(), pubk.data());
		assertEquals( 0, res );
	}

	string dstMessage;
	dstMessage.resize(srcMessage.size());
	{
		int res = mcleece_crypto_box_seal_open(reinterpret_cast<unsigned char*>(dstMessage.data()), cipherText.data(), cipherText.size(), pubk.data(), secret.data());
		assertEquals(0, res);
	}

	assertEquals( "hello friends", dstMessage );
}


TEST_CASE( "easyTest/testNomallocRoundtrip", "[unit]" )
{
	// alternative API to reuse the input buffer for output...
	std::vector<unsigned char> pubk;
	pubk.resize(mcleece_crypto_box_PUBLIC_KEY_SIZE);

	std::vector<unsigned char> secret;
	secret.resize(mcleece_crypto_box_SECRET_KEY_SIZE);

	{
		int res = mcleece_crypto_box_keypair(pubk.data(), secret.data());
		assertEquals( 0, res );
	}

	string message = "hello friends";
	message.resize(message.size() + mcleece_crypto_box_MESSAGE_HEADER_SIZE);

	{
		std::vector<unsigned char> scratch;
		scratch.resize(message.size() - mcleece_MESSAGE_HEADER_SIZE);
		int res = mcleece_cbox_seal_nomalloc(reinterpret_cast<unsigned char*>(message.data()), message.size(), scratch.data(), pubk.data());
		assertEquals( 0, res );
	}

	// message is now our encrypted buffer
	assertTrue( message.substr(5) != "hello" );

	{
		std::vector<unsigned char> scratch;
		scratch.resize(message.size() - mcleece_MESSAGE_HEADER_SIZE);
		int res = mcleece_cbox_seal_open_nomalloc(reinterpret_cast<unsigned char*>(message.data()), message.size(), scratch.data(), pubk.data(), secret.data());
		assertEquals(0, res);
	}

	assertEquals( "hello friends", message );
}

