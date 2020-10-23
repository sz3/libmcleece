/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#include "unittest.h"

#include "serialize/b64_outstream.h"
#include <iostream>
#include <sstream>
#include <string>

using std::string;


TEST_CASE( "b64_outstreamTest/testEncode.Simple", "[unit]" )
{
	std::stringstream ss;
	b64_outstream bs(ss);

	bs << "hello friends";

	assertEquals( "aGVsbG8gZnJpZW5k", ss.str() );

	assertTrue( bs.flush() );
	assertEquals( "aGVsbG8gZnJpZW5kcw==", ss.str() );

	assertFalse( bs.flush() );
	assertEquals( "aGVsbG8gZnJpZW5kcw==", ss.str() );
}

TEST_CASE( "b64_streamTest/testEncode.FlushOnDestructor", "[unit]" )
{
	std::stringstream ss;
	{
		b64_outstream bs(ss);
		bs << "hello friends";
	}

	assertEquals( "aGVsbG8gZnJpZW5kcw==", ss.str() );
}
