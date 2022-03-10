/* This code is subject to the terms of the Mozilla Public License, v.2.0. http://mozilla.org/MPL/2.0/. */
#include "mcleece.h"

#include "actions.h"
#include "cbox.h"
#include "constants.h"
#include "message.h"
#include "simple.h"
#include "util/byte_view.h"
#include <fstream>

using std::string;

extern "C" {

const unsigned mcleece_simple_PUBLIC_KEY_SIZE = mcleece::public_key_simple::size();
const unsigned mcleece_simple_SECRET_KEY_SIZE = mcleece::private_key_simple::size();
const unsigned mcleece_simple_MESSAGE_HEADER_SIZE = mcleece::simple::MESSAGE_HEADER_SIZE;

const unsigned mcleece_crypto_box_PUBLIC_KEY_SIZE = mcleece::cbox::PUBLIC_KEY_SIZE;
const unsigned mcleece_crypto_box_SODIUM_PUBLIC_KEY_SIZE = mcleece::cbox::SODIUM_PUBLIC_KEY_SIZE;
const unsigned mcleece_crypto_box_SECRET_KEY_SIZE = mcleece::cbox::SECRET_KEY_SIZE;
const unsigned mcleece_crypto_box_SODIUM_MESSAGE_HEADER_SIZE = mcleece::cbox::SODIUM_MESSAGE_HEADER_SIZE;
const unsigned mcleece_crypto_box_MESSAGE_HEADER_SIZE = mcleece::cbox::FULL_MESSAGE_HEADER_SIZE;

const int mcleece_MODE_SIMPLE = mcleece::SIMPLE;
const int mcleece_MODE_CRYPTO_BOX = mcleece::CBOX;

int mcleece_simple_keypair(unsigned char* pubk, unsigned char* secret)
{
	mcleece::public_key_simple pk(pubk);
	mcleece::private_key_simple sk(secret);
	return mcleece::simple::keypair(pk, sk);
}

int mcleece_crypto_box_keypair(unsigned char* pubk, unsigned char* secret)
{
	mcleece::public_key_cbox pk(pubk);
	mcleece::private_key_cbox sk(secret);
	return mcleece::cbox::crypto_box_keypair(pk, sk);
}

int mcleece_simple_encrypt(unsigned char* ciphertext_out, const unsigned char* msg, unsigned msg_length, unsigned char* recipient_pubk)
{
	mcleece::byte_view is(msg, msg_length);
	mcleece::byte_view os(ciphertext_out, msg_length + mcleece_simple_MESSAGE_HEADER_SIZE);
	mcleece::public_key_simple rpk(recipient_pubk);
	return mcleece::simple::encrypt(os, is, rpk);
}

int mcleece_simple_decrypt(unsigned char* decrypted_out, const unsigned char* ciphertext, unsigned ciphertext_length, unsigned char* recipient_secret)
{
	mcleece::byte_view is(ciphertext, ciphertext_length);
	mcleece::byte_view os(decrypted_out, ciphertext_length - mcleece_simple_MESSAGE_HEADER_SIZE);
	mcleece::private_key_simple rsk(recipient_secret);
	return mcleece::simple::decrypt(os, is, rsk);
}

int mcleece_crypto_box_seal(unsigned char* ciphertext_out, const unsigned char* msg, unsigned msg_length, unsigned char* recipient_pubk)
{
	mcleece::byte_view is(msg, msg_length);
	mcleece::byte_view os(ciphertext_out, msg_length + mcleece_crypto_box_MESSAGE_HEADER_SIZE);
	mcleece::public_key_cbox rpk(recipient_pubk);
	return mcleece::cbox::crypto_box_seal(os, is, rpk);
}

int mcleece_crypto_box_seal_open(unsigned char* decrypted_out, const unsigned char* ciphertext, unsigned ciphertext_length, unsigned char* recipient_pubk, unsigned char* recipient_secret)
{
	mcleece::byte_view is(ciphertext, ciphertext_length);
	mcleece::byte_view os(decrypted_out, ciphertext_length - mcleece_crypto_box_MESSAGE_HEADER_SIZE);
	mcleece::public_key_sodium rpk(recipient_pubk);
	mcleece::private_key_cbox rsk(recipient_secret);
	return mcleece::cbox::crypto_box_seal_open(os, is, rpk, rsk);
}

int mcleece_inplace_crypto_box_seal(unsigned char* buff, unsigned msg_and_header_length, unsigned char* scratch, unsigned char* recipient_pubk)
{
	mcleece::byte_view inout(buff, msg_and_header_length);
	mcleece::byte_view scr(scratch, msg_and_header_length - mcleece_simple_MESSAGE_HEADER_SIZE); // aka: msg_length + crypto_box_SEALBYTES
	mcleece::public_key_cbox rpk(recipient_pubk);
	return mcleece::cbox::inplace_crypto_box_seal(inout, scr, rpk);
}

int mcleece_inplace_crypto_box_seal_open(unsigned char* buff, unsigned ciphertext_length, unsigned char* scratch, unsigned char* recipient_pubk, unsigned char* recipient_secret)
{
	mcleece::byte_view inout(buff, ciphertext_length);
	mcleece::byte_view scr(scratch, ciphertext_length - mcleece_simple_MESSAGE_HEADER_SIZE); // aka: msg_length + crypto_box_SEALBYTES
	mcleece::public_key_sodium rpk(recipient_pubk);
	mcleece::private_key_cbox rsk(recipient_secret);
	return mcleece::cbox::inplace_crypto_box_seal_open(inout, scr, rpk, rsk);
}

int mcleece_keypair_to_file(const char* keypath, unsigned keypath_len, const char* pw, unsigned pw_length, int mode)
{
	return mcleece::actions::keypair_to_file(string(keypath, keypath_len), string(pw, pw_length), mode);
}

int mcleece_encrypt_file(char* keypath, unsigned keypath_len, char* srcpath, unsigned srcpath_len, char* dstpath, unsigned dstpath_len, int mode)
{
	std::ifstream istream(string(srcpath, srcpath_len), std::ios::binary);
	std::ofstream f(string(dstpath, dstpath_len), std::ios::binary);
	return mcleece::actions::encrypt(string(keypath, keypath_len), istream, f, mode);
}

int mcleece_encrypt_stdout(char* keypath, unsigned keypath_len, char* srcpath, unsigned srcpath_len, int mode)
{
	std::ifstream istream(string(srcpath, srcpath_len), std::ios::binary);
	return mcleece::actions::encrypt(string(keypath, keypath_len), istream, std::cout, mode);
}

int mcleece_decrypt_file(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length, char* srcpath, unsigned srcpath_len, char* dstpath, unsigned dstpath_len, int mode)
{
	std::ifstream istream(string(srcpath, srcpath_len), std::ios::binary);
	std::ofstream f(string(dstpath, dstpath_len), std::ios::binary);
	return mcleece::actions::decrypt(string(keypath, keypath_len), string(pw, pw_length), istream, f, mode);
}

int mcleece_decrypt_stdout(char* keypath, unsigned keypath_len, char* pw, unsigned pw_length, char* srcpath, unsigned srcpath_len, int mode)
{
	std::ifstream istream(string(srcpath, srcpath_len), std::ios::binary);
	return mcleece::actions::decrypt(string(keypath, keypath_len), string(pw, pw_length), istream, std::cout, mode);
}

}

