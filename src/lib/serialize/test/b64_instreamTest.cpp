/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#include "unittest.h"

#include "serialize/b64_instream.h"
#include <iostream>
#include <sstream>
#include <string>

using std::string;


TEST_CASE( "b64_instreamTest/testDecode.Simple", "[unit]" )
{
	std::stringstream ss;
	ss << "aGVsbG8gZnJpZW5kcw==";
	b64_instream bs(ss);

	assertTrue(bs);

	std::string buff;
	buff.resize(20);

	bs.read(buff.data(), buff.size());
	assertEquals(13, bs.gcount());
	buff.resize(bs.gcount());

	assertFalse(bs);

	assertEquals( "hello friends", buff );
}

TEST_CASE( "b64_instreamTest/testDecode.Piecemeal", "[unit]" )
{
	std::stringstream ss;
	ss << "aGVsbG8gZnJpZW5kcw==";
	b64_instream bs(ss);

	assertTrue(bs);

	std::string buff;
	buff.resize(6);

	bs.read(buff.data(), buff.size());
	assertEquals(6, bs.gcount());
	assertEquals( "hello ", buff );

	assertTrue( bs );

	bs.read(buff.data(), buff.size());
	assertEquals(6, bs.gcount());
	buff.resize(bs.gcount());
	assertEquals( "friend", buff );

	assertTrue( bs );

	bs.read(buff.data(), buff.size());
	assertEquals(1, bs.gcount());
	buff.resize(bs.gcount());
	assertEquals( "s", buff );

	assertFalse( bs );

	bs.read(buff.data(), buff.size());
	assertEquals(0, bs.gcount());
	buff.resize(bs.gcount());
	assertEquals( "", buff );
}
