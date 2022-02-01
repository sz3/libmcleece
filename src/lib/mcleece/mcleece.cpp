/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#include "mcleece.h"

#include "actions.h"
#include "serialize/b64_instream.h"
#include "serialize/b64_outstream.h"
#include <fstream>

using std::string;

extern "C" {

int mcleece_keypair(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length)
{
	return mcleece::actions::keypair(string(keypath, keypath_len), string(pw, pw_length));
}

int mcleece_encrypt(char* keypath, unsigned keypath_len, char* srcpath, unsigned srcpath_len, char* dstpath, unsigned dstpath_len, int flags)
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

int mcleece_decrypt(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length, char* srcpath, unsigned srcpath_len, char* dstpath, unsigned dstpath_len, int flags)
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

