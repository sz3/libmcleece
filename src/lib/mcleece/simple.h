/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#pragma once

#include "constants.h"
#include "keygen.h"
#include "message.h"

#include "serialize/format.h"
#include "util/byte_view.h"
#include <string>
#include <sstream>
#include <vector>

// return codes attempt to match https://www.freebsd.org/cgi/man.cgi?query=sysexits
// ... emphasis on "attempt". I think of it like picking from HTTP status codes...

namespace mcleece {
namespace simple {
	static const unsigned MESSAGE_HEADER_SIZE = mcleece::message::session_header_size() + crypto_secretbox_macbytes();

	inline int keypair(mcleece::public_key_simple& pubk, mcleece::private_key_simple& secret)
	{
		return mcleece::keygen::generate_keypair(pubk, secret);
	}

	inline int encrypt(mcleece::byte_view output_c, mcleece::byte_view message, const mcleece::public_key_simple& pubk)
	{
		mcleece::session_key session = mcleece::keygen::generate_session_key(pubk);
		mcleece::nonce n;

		// store session data first
		if (!mcleece::message::encode_session(output_c, session, n))
			return 66;
		if (!output_c.size())
			return 67;

		// it's all in RAM -- single chunk encode
		int res = mcleece::message::encrypt(output_c, message, session, n);
		if (res != 0)
			return 69 + res;

		return 0;
	}

	inline int decrypt(mcleece::byte_view output_m, mcleece::byte_view ciphertext, const mcleece::private_key_simple& secret)
	{
		// extract the session from the front of the input
		if (ciphertext.size() < MESSAGE_HEADER_SIZE)
			return 65;
		auto session_nonce = mcleece::message::decode_session(ciphertext, secret);
		if (!session_nonce)
			return 64;
		if (!ciphertext.advance(mcleece::message::session_header_size()))
			return 65;

		mcleece::session_key& enc_session = session_nonce->first;
		mcleece::nonce& enc_n = session_nonce->second;

		// extract the message bytes
		int res = mcleece::message::decrypt(output_m, ciphertext, enc_session, enc_n);
		if (res != 0)
			return 69 + res;

		return 0;
	}

}}
