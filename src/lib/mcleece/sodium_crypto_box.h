// MIT?
#pragma once

#include "sodium/crypto_box.h"
#include "sodium/crypto_generichash.h"
#include "sodium/crypto_secretbox.h"
#include <algorithm>

namespace mcleece {

class sodium_crypto_box
{
public:
	sodium_crypto_box(const unsigned char* pk, const unsigned char* sk=nullptr)
	    : _pk(pk)
	    , _sk(sk)
	{}

protected:
	int compute_nonce(unsigned char *nonce, const unsigned char *pk1, const unsigned char *pk2)
	{
		crypto_generichash_state st;
		crypto_generichash_init(&st, NULL, 0U, crypto_box_NONCEBYTES);
		crypto_generichash_update(&st, pk1, crypto_box_PUBLICKEYBYTES);
		crypto_generichash_update(&st, pk2, crypto_box_PUBLICKEYBYTES);
		crypto_generichash_final(&st, nonce, crypto_box_NONCEBYTES);
		return 0;
	}

public:
	int seal(unsigned char* c, const unsigned char* m, unsigned long long mlen)
	{
		unsigned char nonce[crypto_box_NONCEBYTES];
		unsigned char epk[crypto_box_PUBLICKEYBYTES];
		unsigned char esk[crypto_box_SECRETKEYBYTES];

		// ephemeral keypair
		if (crypto_box_keypair(epk, esk) != 0)
			return -1;

		// compute nonce
		compute_nonce(nonce, epk, _pk);

		// generate secret key
		// TODO: assert crypto_box_BEFORENMBYTES >= crypto_secretbox_KEYBYTES
		unsigned char k[crypto_box_BEFORENMBYTES];
		::crypto_box_beforenm(k, _pk, esk);


		int ret = ::crypto_secretbox_easy(c + crypto_box_PUBLICKEYBYTES, m, mlen, nonce, k);

		std::copy(epk, epk+crypto_box_PUBLICKEYBYTES, c);
		// TODO: zero out memory
		/*sodium_memzero(esk, sizeof esk);
		sodium_memzero(epk, sizeof epk);
		sodium_memzero(nonce, sizeof nonce);*/

		return ret;
	}

	int seal_open(unsigned char* m, const unsigned char* c, unsigned long long clen)
	{
		if (_sk == nullptr)
			return -2;

		return ::crypto_box_seal_open(m, c, clen, _pk, _sk);
	}

protected:
	const unsigned char* _pk;
	const unsigned char* _sk;
};

}
