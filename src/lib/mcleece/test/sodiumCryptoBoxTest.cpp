/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#include "unittest.h"

#include "mcleece/sodium_crypto_box.h"

#include <string>
#include <vector>

using std::string;

TEST_CASE( "sodiumCryptoBoxTest/testCryptoBoxSeal", "[unit]" )
{
	std::vector<unsigned char> pubk;
	pubk.resize(crypto_box_publickeybytes());

	std::vector<unsigned char> secret;
	secret.resize(crypto_box_secretkeybytes());

	{
		int res = crypto_box_keypair(pubk.data(), secret.data());
		assertEquals( 0, res );
	}

	string srcMessage = "hello friends";
	std::vector<unsigned char> cipherText;
	cipherText.resize(srcMessage.size() + crypto_box_sealbytes());
	{
		int res = mcleece::sodium_crypto_box(pubk.data()).seal(cipherText.data(), reinterpret_cast<unsigned char*>(srcMessage.data()), srcMessage.size());
		assertEquals( 0, res );
	}

	string dstMessage;
	dstMessage.resize(srcMessage.size());
	{
		int res = crypto_box_seal_open(reinterpret_cast<unsigned char*>(dstMessage.data()), cipherText.data(), cipherText.size(), pubk.data(), secret.data());
		assertEquals(0, res);
	}

	assertEquals( "hello friends", dstMessage );
}

TEST_CASE( "sodiumCryptoBoxTest/testCryptoBoxSealOpen", "[unit]" )
{
	std::vector<unsigned char> pubk;
	pubk.resize(crypto_box_publickeybytes());

	std::vector<unsigned char> secret;
	secret.resize(crypto_box_secretkeybytes());

	{
		int res = crypto_box_keypair(pubk.data(), secret.data());
		assertEquals( 0, res );
	}

	string srcMessage = "hello friends";
	std::vector<unsigned char> cipherText;
	cipherText.resize(srcMessage.size() + crypto_box_sealbytes());
	{
		int res = crypto_box_seal(cipherText.data(), reinterpret_cast<unsigned char*>(srcMessage.data()), srcMessage.size(), pubk.data());
		assertEquals( 0, res );
	}

	string dstMessage;
	dstMessage.resize(srcMessage.size());
	{
		int res = mcleece::sodium_crypto_box(pubk.data(), secret.data()).seal_open(reinterpret_cast<unsigned char*>(dstMessage.data()), cipherText.data(), cipherText.size());
		assertEquals(0, res);
	}

	assertEquals( "hello friends", dstMessage );
}

TEST_CASE( "sodiumCryptoBoxTest/testCryptoBoxRoundtrip", "[unit]" )
{
	std::vector<unsigned char> pubk;
	pubk.resize(crypto_box_publickeybytes());

	std::vector<unsigned char> secret;
	secret.resize(crypto_box_secretkeybytes());

	{
		int res = crypto_box_keypair(pubk.data(), secret.data());
		assertEquals( 0, res );
	}

	string srcMessage = "hello friendos";
	std::vector<unsigned char> cipherText;
	cipherText.resize(srcMessage.size() + crypto_box_sealbytes());
	{
		int res = mcleece::sodium_crypto_box(pubk.data()).seal(cipherText.data(), reinterpret_cast<unsigned char*>(srcMessage.data()), srcMessage.size());
		assertEquals( 0, res );
	}

	string dstMessage;
	dstMessage.resize(srcMessage.size());
	{
		int res = mcleece::sodium_crypto_box(pubk.data(), secret.data()).seal_open(reinterpret_cast<unsigned char*>(dstMessage.data()), cipherText.data(), cipherText.size());
		assertEquals(0, res);
	}

	assertEquals( "hello friendos", dstMessage );
}
