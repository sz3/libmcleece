/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#include "unittest.h"
#include "TestHelpers.h"

#include "mcleece/private_key.h"

#include "util/MakeTempDirectory.h"
#include <iostream>
#include <string>

using std::string;
using namespace std;


TEST_CASE( "private_keyTest/testSaveLoad.Simple", "[unit]" )
{
	MakeTempDirectory tempdir;

	mcleece::private_key_simple sec;
	for (unsigned i = 0; i < sec.size(); ++i)
		sec.data()[i] = 48 + (i % 10);

	assertTrue( sec.save(tempdir.path() / "foo.sk", "password") );

	mcleece::private_key rek = mcleece::private_key_simple::from_file(tempdir.path() / "foo.sk", "password");

	string expected(reinterpret_cast<const char*>(sec.data()), sec.size());
	string actual(reinterpret_cast<const char*>(rek.data()), rek.size());
	assertEquals(expected, actual);
}

TEST_CASE( "private_keyTest/testSaveLoad.Cbox", "[unit]" )
{
	MakeTempDirectory tempdir;

	mcleece::private_key_cbox sec;
	for (unsigned i = 0; i < sec.size(); ++i)
		sec.data()[i] = 48 + (i % 10);

	assertTrue( sec.save(tempdir.path() / "foo.sk", "password") );

	mcleece::private_key rek = mcleece::private_key_cbox::from_file(tempdir.path() / "foo.sk", "password");

	string expected(reinterpret_cast<const char*>(sec.data()), sec.size());
	string actual(reinterpret_cast<const char*>(rek.data()), rek.size());
	assertEquals(expected, actual);
}
