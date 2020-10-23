#include "api.h"

#include "actions.h"
#include "serialize/b64_instream.h"
#include "serialize/b64_outstream.h"
#include <fstream>

using std::string;

extern "C" {

int generate_keypair(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length)
{
	return mcleece::actions::generate_keypair(string(keypath, keypath_len), string(pw, pw_length));
}

int encrypt(char* keypath, unsigned keypath_len, char* srcpath, unsigned srcpath_len, char* dstpath, unsigned dstpath_len, int flags)
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

int encrypt_stdout(char* keypath, unsigned keypath_len, char* srcpath, unsigned srcpath_len, int flags)
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

int decrypt(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length, char* srcpath, unsigned srcpath_len, char* dstpath, unsigned dstpath_len, int flags)
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

int decrypt_stdout(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length, char* srcpath, unsigned srcpath_len, int flags)
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

