/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#include "unittest.h"

#include "mcleece/mcleece.h"
#include "util/File.h"
#include "util/MakeTempDirectory.h"

#include <iostream>
#include <fstream>
#include <string>

using std::string;

TEST_CASE( "apiTest/testRoundtrip", "[unit]" )
{
	MakeTempDirectory tempdir;

	string keypath = tempdir.path() / "apitest";
	string password = "password";

	{
		int res = mcleece_generate_keypair(keypath.data(), keypath.size(), password.data(), password.size());
		assertEquals( 0, res );
	}

	string srcPath = tempdir.path() / "helloworld";
	{
		std::ofstream f(srcPath);
		f << "hello friends";
	}

	string encryptedPath = tempdir.path() / "encrypted_msg";
	{
		string pkpath = keypath + ".pk";
		int res = mcleece_encrypt(pkpath.data(), pkpath.size(), srcPath.data(), srcPath.size(), encryptedPath.data(), encryptedPath.size(), 0);
		assertEquals( 0, res );
	}

	string dstPath = tempdir.path() / "decrypted";
	{
		string skpath = keypath + ".sk";
		int res = mcleece_decrypt(skpath.data(), skpath.size(), password.data(), password.size(), encryptedPath.data(), encryptedPath.size(), dstPath.data(), dstPath.size(), 0);
		assertEquals(0, res);
	}

	assertEquals( "hello friends", File(dstPath).read_all() );
}

TEST_CASE( "apiTest/testRoundtrip.b64", "[unit]" )
{
	MakeTempDirectory tempdir;

	string keypath = tempdir.path() / "test";
	string password = "password";
	TestHelpers::generate_keypair(keypath);

	{
		int res = mcleece_generate_keypair(keypath.data(), keypath.size(), password.data(), password.size());
		assertEquals( 0, res );
	}

	string srcPath = tempdir.path() / "helloworld";
	{
		std::ofstream f(srcPath);
		f << "hello friends";
	}

	string encryptedPath = tempdir.path() / "encrypted_msg";
	{
		string pkpath = keypath + ".pk";
		int res = mcleece_encrypt(pkpath.data(), pkpath.size(), srcPath.data(), srcPath.size(), encryptedPath.data(), encryptedPath.size(), mcleece_flag_base64);
		assertEquals( 0, res );
	}

	string dstPath = tempdir.path() / "decrypted";
	{
		string skpath = keypath + ".sk";
		int res = mcleece_decrypt(skpath.data(), skpath.size(), password.data(), password.size(), encryptedPath.data(), encryptedPath.size(), dstPath.data(), dstPath.size(), mcleece_flag_base64);
		assertEquals(0, res);
	}

	assertEquals( "hello friends", File(dstPath).read_all() );
}
