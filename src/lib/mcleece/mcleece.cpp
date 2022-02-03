/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#include "mcleece.h"

#include "actions.h"
#include "message.h"
#include "serialize/b64_instream.h"
#include "serialize/b64_outstream.h"
#include "util/byte_view.h"
#include <fstream>

using std::string;

extern "C" {

const unsigned mcleece_PUBLIC_KEY_SIZE = mcleece::public_key::size();
const unsigned mcleece_SECRET_KEY_SIZE = mcleece::private_key::size();
const unsigned mcleece_MESSAGE_HEADER_SIZE = mcleece::actions::MESSAGE_HEADER_SIZE;

int mcleece_keypair(unsigned char* pubk, unsigned char* secret)
{
	return mcleece::actions::keypair(pubk, secret);
}

int mcleece_keypair_to_file(const char* keypath, unsigned keypath_len, const char* pw, unsigned pw_length)
{
	return mcleece::actions::keypair_to_file(string(keypath, keypath_len), string(pw, pw_length));
}

int mcleece_encrypt(unsigned char* ciphertext, const unsigned char* msg, unsigned msg_length, unsigned char* recipient_pubk)
{
	mcleece::byte_view is(msg, msg_length);
	mcleece::byte_view os(ciphertext, msg_length + mcleece_MESSAGE_HEADER_SIZE);
	return mcleece::actions::encrypt(recipient_pubk, is, os);
}

int mcleece_decrypt(unsigned char* decrypted, const unsigned char* ciphertext, unsigned ciphertext_length, unsigned char* recipient_secret)
{
	mcleece::byte_view is(ciphertext, ciphertext_length);
	mcleece::byte_view os(decrypted, ciphertext_length - mcleece_MESSAGE_HEADER_SIZE);
	return mcleece::actions::decrypt(recipient_secret, is, os);
}

int mcleece_encrypt_file(char* keypath, unsigned keypath_len, char* srcpath, unsigned srcpath_len, char* dstpath, unsigned dstpath_len, int flags)
{
	std::ifstream istream(string(srcpath, srcpath_len), std::ios::binary);
	std::ofstream f(string(dstpath, dstpath_len), std::ios::binary);

	if (flags & mcleece_flag_base64)
	{
		b64_outstream bo(f);
		return mcleece::actions::encrypt(string(keypath, keypath_len), istream, bo);
	}
	else
		return mcleece::actions::encrypt(string(keypath, keypath_len), istream, f);
}

int mcleece_encrypt_stdout(char* keypath, unsigned keypath_len, char* srcpath, unsigned srcpath_len, int flags)
{
	std::ifstream istream(string(srcpath, srcpath_len), std::ios::binary);

	if (flags & mcleece_flag_base64)
	{
		b64_outstream bo(std::cout);
		return mcleece::actions::encrypt(string(keypath, keypath_len), istream, bo);
	}
	else
		return mcleece::actions::encrypt(string(keypath, keypath_len), istream, std::cout);
}

int mcleece_decrypt_file(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length, char* srcpath, unsigned srcpath_len, char* dstpath, unsigned dstpath_len, int flags)
{
	std::ifstream istream(string(srcpath, srcpath_len), std::ios::binary);
	std::ofstream f(string(dstpath, dstpath_len), std::ios::binary);

	if (flags & mcleece_flag_base64)
	{
		b64_instream bi(istream);
		return mcleece::actions::decrypt(string(keypath, keypath_len), string(pw, pw_length), bi, f);
	}
	else
		return mcleece::actions::decrypt(string(keypath, keypath_len), string(pw, pw_length), istream, f);
}

int mcleece_decrypt_stdout(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length, char* srcpath, unsigned srcpath_len, int flags)
{
	std::ifstream istream(string(srcpath, srcpath_len), std::ios::binary);

	if (flags & mcleece_flag_base64)
	{
		b64_instream bi(istream);
		return mcleece::actions::decrypt(string(keypath, keypath_len), string(pw, pw_length), bi, std::cout);
	}
	else
		return mcleece::actions::decrypt(string(keypath, keypath_len), string(pw, pw_length), istream, std::cout);
}

}

