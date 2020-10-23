#include "api.h"

#include "actions.h"
#include "serialize/b64_instream.h"
#include "serialize/b64_outstream.h"
#include <fstream>

using std::string;

int generate_keypair(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length)
{
	return mcleece::actions::generate_keypair(string(keypath, keypath_len), string(pw, pw_length));
}

int encrypt(char* keypath, unsigned keypath_len, char* srcpath, unsigned srcpath_len, char* dstpath, unsigned dstpath_len)
{
	std::ifstream istream(string(srcpath, srcpath_len), std::ios::binary);
	std::ofstream f(string(dstpath, dstpath_len), std::ios::binary);
	mcleece::actions::encrypt(string(keypath, keypath_len), istream, f);
}

int encrypt_b64(char* keypath, unsigned keypath_len, char* srcpath, unsigned srcpath_len, char* dstpath, unsigned dstpath_len)
{
	std::ifstream istream(string(srcpath, srcpath_len), std::ios::binary);
	std::ofstream f(string(dstpath, dstpath_len), std::ios::binary);
	b64_outstream bo(f);
	mcleece::actions::encrypt(string(keypath, keypath_len), istream, bo);
}

int encrypt_stdout(char* keypath, unsigned keypath_len, char* srcpath, unsigned srcpath_len)
{
	std::ifstream istream(string(srcpath, srcpath_len), std::ios::binary);
	mcleece::actions::encrypt(string(keypath, keypath_len), istream, std::cout);
}

int encrypt_stdout_b64(char* keypath, unsigned keypath_len, char* srcpath, unsigned srcpath_len)
{
	std::ifstream istream(string(srcpath, srcpath_len), std::ios::binary);
	b64_outstream bo(std::cout);
	mcleece::actions::encrypt(string(keypath, keypath_len), istream, bo);
}

int decrypt(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length, char* srcpath, unsigned srcpath_len, char* dstpath, unsigned dstpath_len)
{
	std::ifstream istream(string(srcpath, srcpath_len), std::ios::binary);
	std::ofstream f(string(dstpath, dstpath_len), std::ios::binary);
	mcleece::actions::decrypt(string(keypath, keypath_len), string(pw, pw_length), istream, f);
}

int decrypt_b64(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length, char* srcpath, unsigned srcpath_len, char* dstpath, unsigned dstpath_len)
{
	std::ifstream istream(string(srcpath, srcpath_len), std::ios::binary);
	b64_instream bi(istream);
	std::ofstream f(string(dstpath, dstpath_len), std::ios::binary);
	mcleece::actions::decrypt(string(keypath, keypath_len), string(pw, pw_length), bi, f);
}

int decrypt_stdout(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length, char* srcpath, unsigned srcpath_len)
{
	std::ifstream istream(string(srcpath, srcpath_len), std::ios::binary);
	mcleece::actions::decrypt(string(keypath, keypath_len), string(pw, pw_length), istream, std::cout);
}

int decrypt_stdout_b64(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length, char* srcpath, unsigned srcpath_len)
{
	std::ifstream istream(string(srcpath, srcpath_len), std::ios::binary);
	b64_instream bi(istream);
	mcleece::actions::decrypt(string(keypath, keypath_len), string(pw, pw_length), bi, std::cout);
}
