#pragma once

#include "keygen.h"
#include "message.h"

#include "base64/base.hpp"
#include "serialize/format.h"
#include <cstdio>
#include <string>
#include <vector>

namespace mcleece {
namespace actions {
	int generate_keypair(std::string keypath)
	{
		int res = mcleece::generate_keypair(fmt::format("{}.pk", keypath), fmt::format("{}.sk", keypath));
		return res;
	}

	template <typename OUTSTREAM>
	int encrypt(std::string keypath, std::string infile, OUTSTREAM& os)
	{
		mcleece::public_key pubk(keypath);

		// limit is arbitrarily set at ~50MB. For files larger than that, chunk them up into multiple messages
		mcleece::session_key session = mcleece::generate_session_key(pubk);
		mcleece::nonce n;

		std::string ciphertext = mcleece::encrypt(session, "hello world", n);
		if (ciphertext.empty())
			return 500;

		std::string sessiontext = mcleece::encode_session(session, n);
		os << sessiontext << ciphertext;
		return 0;
	}

	template <typename OUTSTREAM>
	int decrypt(std::string keypath, std::string infile, OUTSTREAM& os)
	{
		// read some bytes -- we'll try to decode a session, first.
		// base64 check will either be done as a flag, or via stream magic

		mcleece::private_key secret(keypath);

		// ifstream's api is bad and I'd rather just use fread()
		FILE* f = fopen(infile.c_str(), "rb");
		if (f == NULL)
			return 404;

		// extract the session from the front of the file
		char buff[8192];
		size_t last_read = fread(buff, 1, mcleece::encoded_session_size(), f);
		if (last_read < mcleece::encoded_session_size())
			return 410;
		auto session_nonce = mcleece::decode_session(secret, buff, last_read);
		if (!session_nonce)
			return 411;
		mcleece::session_key& enc_session = session_nonce->first;
		mcleece::nonce& enc_n = session_nonce->second;

		// read the message bytes
		std::string rec_ciphertext;
		while (last_read = fread(buff, 1, 8192, f))
		{
			rec_ciphertext.append(std::string(buff, buff+last_read));
			if (last_read < 8192)
				break;
		}

		// decrypt the message
		std::string message = mcleece::decrypt(enc_session, rec_ciphertext, enc_n);
		os << message;
		return 0;
	}
}}
