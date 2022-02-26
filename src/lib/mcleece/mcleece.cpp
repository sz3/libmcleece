/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#include "mcleece.h"

#include "actions.h"
#include "constants.h"
#include "easy.h"
#include "message.h"
#include "util/byte_view.h"
#include <fstream>

using std::string;

extern "C" {

const unsigned mcleece_simple_PUBLIC_KEY_SIZE = mcleece::public_key_simple::size();
const unsigned mcleece_simple_SECRET_KEY_SIZE = mcleece::private_key<mcleece::SIMPLE>::size();
const unsigned mcleece_simple_MESSAGE_HEADER_SIZE = mcleece::actions::MESSAGE_HEADER_SIZE;

const unsigned mcleece_crypto_box_PUBLIC_KEY_SIZE = mcleece::easy::PUBLIC_KEY_SIZE;
const unsigned mcleece_crypto_box_SECRET_KEY_SIZE = mcleece::easy::SECRET_KEY_SIZE;
const unsigned mcleece_crypto_box_MESSAGE_HEADER_SIZE = mcleece::easy::FULL_MESSAGE_HEADER_SIZE;

const int mcleece_MODE_SIMPLE = mcleece::SIMPLE;
const int mcleece_MODE_CRYPTO_BOX = mcleece::CBOX;

int mcleece_simple_keypair(unsigned char* pubk, unsigned char* secret)
{
	mcleece::public_key_simple pk(pubk);
	mcleece::private_key_simple sk(secret);
	return mcleece::actions::keypair(pk, sk);
}

int mcleece_keypair_to_file(const char* keypath, unsigned keypath_len, const char* pw, unsigned pw_length, int mode)
{
	return mcleece::actions::keypair_to_file(string(keypath, keypath_len), string(pw, pw_length), mode);
}

int mcleece_crypto_box_keypair(unsigned char* pubk, unsigned char* secret)
{
	return mcleece::easy::crypto_box_keypair(pubk, secret);
}

int mcleece_simple_encrypt(unsigned char* ciphertext_out, const unsigned char* msg, unsigned msg_length, unsigned char* recipient_pubk)
{
	mcleece::byte_view is(msg, msg_length);
	mcleece::byte_view os(ciphertext_out, msg_length + mcleece_simple_MESSAGE_HEADER_SIZE);
	return mcleece::actions::encrypt(os, is, recipient_pubk);
}

int mcleece_simple_decrypt(unsigned char* decrypted_out, const unsigned char* ciphertext, unsigned ciphertext_length, unsigned char* recipient_secret)
{
	mcleece::byte_view is(ciphertext, ciphertext_length);
	mcleece::byte_view os(decrypted_out, ciphertext_length - mcleece_simple_MESSAGE_HEADER_SIZE);
	return mcleece::actions::decrypt(os, is, recipient_secret);
}

int mcleece_crypto_box_seal(unsigned char* ciphertext_out, const unsigned char* msg, unsigned msg_length, unsigned char* recipient_pubk)
{
	mcleece::byte_view is(msg, msg_length);
	mcleece::byte_view os(ciphertext_out, msg_length + mcleece_crypto_box_MESSAGE_HEADER_SIZE);
	return mcleece::easy::crypto_box_seal(os, is, recipient_pubk);
}

int mcleece_crypto_box_seal_open(unsigned char* decrypted_out, const unsigned char* ciphertext, unsigned ciphertext_length, unsigned char* recipient_pubk, unsigned char* recipient_secret)
{
	mcleece::byte_view is(ciphertext, ciphertext_length);
	mcleece::byte_view os(decrypted_out, ciphertext_length - mcleece_crypto_box_MESSAGE_HEADER_SIZE);
	return mcleece::easy::crypto_box_seal_open(os, is, recipient_pubk, recipient_secret);
}

int mcleece_inplace_crypto_box_seal(unsigned char* buff, unsigned msg_and_header_length, unsigned char* scratch, unsigned char* recipient_pubk)
{
	mcleece::byte_view inout(buff, msg_and_header_length);
	mcleece::byte_view scr(scratch, msg_and_header_length - mcleece_simple_MESSAGE_HEADER_SIZE); // aka: msg_length + crypto_box_SEALBYTES
	return mcleece::easy::inplace_crypto_box_seal(inout, scr, recipient_pubk);
}

int mcleece_inplace_crypto_box_seal_open(unsigned char* buff, unsigned ciphertext_length, unsigned char* scratch, unsigned char* recipient_pubk, unsigned char* recipient_secret)
{
	mcleece::byte_view inout(buff, ciphertext_length);
	mcleece::byte_view scr(scratch, ciphertext_length - mcleece_simple_MESSAGE_HEADER_SIZE); // aka: msg_length + crypto_box_SEALBYTES
	return mcleece::easy::inplace_crypto_box_seal_open(inout, scr, recipient_pubk, recipient_secret);
}

int mcleece_encrypt_file(char* keypath, unsigned keypath_len, char* srcpath, unsigned srcpath_len, char* dstpath, unsigned dstpath_len, int flags)
{
	std::ifstream istream(string(srcpath, srcpath_len), std::ios::binary);
	std::ofstream f(string(dstpath, dstpath_len), std::ios::binary);
	return mcleece::actions::encrypt(string(keypath, keypath_len), istream, f);
}

int mcleece_encrypt_stdout(char* keypath, unsigned keypath_len, char* srcpath, unsigned srcpath_len, int flags)
{
	std::ifstream istream(string(srcpath, srcpath_len), std::ios::binary);
	return mcleece::actions::encrypt(string(keypath, keypath_len), istream, std::cout);
}

int mcleece_decrypt_file(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length, char* srcpath, unsigned srcpath_len, char* dstpath, unsigned dstpath_len, int flags)
{
	std::ifstream istream(string(srcpath, srcpath_len), std::ios::binary);
	std::ofstream f(string(dstpath, dstpath_len), std::ios::binary);
	return mcleece::actions::decrypt(string(keypath, keypath_len), string(pw, pw_length), istream, f);
}

int mcleece_decrypt_stdout(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length, char* srcpath, unsigned srcpath_len, int flags)
{
	std::ifstream istream(string(srcpath, srcpath_len), std::ios::binary);
	return mcleece::actions::decrypt(string(keypath, keypath_len), string(pw, pw_length), istream, std::cout);
}

}

