/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#include "unittest.h"

#include "mcleece/mcleece.h"

#include <string>
#include <vector>

using std::string;

TEST_CASE( "cboxTest/testRoundtrip", "[unit]" )
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

TEST_CASE( "cboxTest/testInplaceRoundtrip", "[unit]" )
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

	string srcMessage = "hello friends";

	string data = srcMessage;
	data.resize(srcMessage.size() + mcleece_crypto_box_MESSAGE_HEADER_SIZE);
	assertTrue( data.substr(0, 5) == "hello" );

	{
		std::vector<unsigned char> scratch;
		scratch.resize(data.size() - mcleece_simple_MESSAGE_HEADER_SIZE);
		int res = mcleece_inplace_crypto_box_seal(reinterpret_cast<unsigned char*>(data.data()), data.size(), scratch.data(), pubk.data());
		assertEquals( 0, res );

		// assert we can decrypt the libsodium part from `scratch`??
	}

	// data is now our encrypted buffer
	assertTrue( data.substr(0, 5) != "hello" );

	{
		std::vector<unsigned char> scratch;
		scratch.resize(data.size() - mcleece_simple_MESSAGE_HEADER_SIZE);
		int res = mcleece_inplace_crypto_box_seal_open(reinterpret_cast<unsigned char*>(data.data()), data.size(), scratch.data(), pubk.data(), secret.data());
		assertEquals(0, res);
	}

	string dstMessage = data.substr(0, srcMessage.size());
	assertEquals( "hello friends", dstMessage );
}

TEST_CASE( "cboxTest/testCrossValidation.1", "[unit]" )
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
	string cipherText;
	cipherText.resize(srcMessage.size() + mcleece_crypto_box_MESSAGE_HEADER_SIZE);
	{
		int res = mcleece_crypto_box_seal(reinterpret_cast<unsigned char*>(cipherText.data()), reinterpret_cast<unsigned char*>(srcMessage.data()), srcMessage.size(), pubk.data());
		assertEquals( 0, res );
	}

	std::vector<unsigned char> scratch;
	scratch.resize(srcMessage.size() + mcleece_crypto_box_SODIUM_MESSAGE_HEADER_SIZE);
	{
		int res = mcleece_inplace_crypto_box_seal_open(reinterpret_cast<unsigned char*>(cipherText.data()), cipherText.size(), scratch.data(), pubk.data(), secret.data());
		assertEquals(0, res);
	}

	string dstMessage = cipherText.substr(0, srcMessage.size());
	assertEquals( "hello friends", dstMessage );
}

TEST_CASE( "cboxTest/testCrossValidation.2", "[unit]" )
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

	string data = srcMessage;
	data.resize(srcMessage.size() + mcleece_crypto_box_MESSAGE_HEADER_SIZE);
	assertTrue( data.substr(0, 5) == "hello" );

	{
		std::vector<unsigned char> scratch;
		scratch.resize(data.size() - mcleece_simple_MESSAGE_HEADER_SIZE);
		int res = mcleece_inplace_crypto_box_seal(reinterpret_cast<unsigned char*>(data.data()), data.size(), scratch.data(), pubk.data());
		assertEquals( 0, res );
	}

	// ciphertext is now in `data`

	string dstMessage;
	dstMessage.resize(srcMessage.size());
	{
		int res = mcleece_crypto_box_seal_open(reinterpret_cast<unsigned char*>(dstMessage.data()), reinterpret_cast<unsigned char*>(data.data()), data.size(), pubk.data(), secret.data());
		assertEquals(0, res);
	}

	assertEquals( "hello friends", dstMessage );
}
