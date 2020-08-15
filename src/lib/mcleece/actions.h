#pragma once

#include "keygen.h"
#include "message.h"

#include "serialize/format.h"
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
	int encrypt(std::string keypath, OUTSTREAM& os)
	{
		mcleece::public_key pubk(keypath);

		// limit is arbitrarily set at ~50MB. For files larger than that, chunk them up into multiple messages
		mcleece::session_key session = mcleece::generate_session_key(pubk);
		mcleece::nonce n;
		std::vector<unsigned char> ciphertext = mcleece::encrypt(session, "hello world", n);

		std::string b64session = mcleece::encode_session(session, n);
		os << b64session << std::endl;
		os << std::endl;
		std::string b64c = mcleece::encode(ciphertext);
		os << b64c << std::endl;
		return 0;
	}

	int decrypt(std::string keypath)
	{
		// we're probably going to try to decode as base64 -- then, if that fails, try to decode as binary
		// probably should check that there are only valid base64 characters, first???

		/*
		mcleece::private_key secret("/tmp/test.sk");
		auto session_nonce = mcleece::decode_session(b64session);
		if (!session_nonce)
			std::cout << "failed decode_session :(" << std::endl;

		std::vector<unsigned char>& enc_session = session_nonce->first;
		mcleece::nonce& enc_n = session_nonce->second;
		vector<unsigned char> rec_ciphertext = mcleece::decode(b64c);

		// decrypt the encrypted key
		mcleece::session_key recoveredSession = mcleece::decode_session_key(secret, enc_session);
		std::string message = mcleece::decrypt(recoveredSession, rec_ciphertext, enc_n);

		std::cout << message << std::endl;*/
		return 0;
	}
}}
