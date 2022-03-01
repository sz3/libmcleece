/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#include "unittest.h"
#include "TestHelpers.h"

#include "mcleece/mcleece.h"
#include "util/File.h"
#include "util/MakeTempDirectory.h"

#include <iostream>
#include <fstream>
#include <string>

using std::string;

TEST_CASE( "apiCliTest/testFileRoundtrip", "[unit]" )
{
	MakeTempDirectory tempdir;

	string keypath = tempdir.path() / "apitest";
	string password = "password";

	{
		int res = mcleece_keypair_to_file(keypath.data(), keypath.size(), password.data(), password.size(), mcleece::SIMPLE);
		assertEquals( 0, res );
	}

	string srcPath = tempdir.path() / "helloworld";
	{
		std::ofstream f(srcPath);
		f << "hello friends";
	}

	string encryptedPath = tempdir.path() / "encrypted_msg";
	{
		int res = mcleece_encrypt_file(keypath.data(), keypath.size(), srcPath.data(), srcPath.size(), encryptedPath.data(), encryptedPath.size(), 0);
		assertEquals( 0, res );
	}

	string dstPath = tempdir.path() / "decrypted";
	{
		int res = mcleece_decrypt_file(keypath.data(), keypath.size(), password.data(), password.size(), encryptedPath.data(), encryptedPath.size(), dstPath.data(), dstPath.size(), 0);
		assertEquals(0, res);
	}

	assertEquals( "hello friends", File(dstPath).read_all() );
}
