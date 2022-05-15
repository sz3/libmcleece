// refactored/modified from libsodium crypto_box_seal
/*
 * ISC License
 *
 * Copyright (c) 2013-2022
 * Frank Denis <j at pureftpd dot org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#pragma once

#include "util/byte_view.h"

#include "sodium/crypto_box.h"
#include "sodium/crypto_generichash.h"
#include "sodium/crypto_secretbox.h"
#include <algorithm>
#include <functional>

// namespace not_sodium?
namespace mcleece {

class sodium_crypto_box
{
public:
	sodium_crypto_box(const unsigned char* pk, const unsigned char* sk=nullptr)
		: _pk(pk)
		, _sk(sk)
	{}

	sodium_crypto_box& mix(const std::function<bool(mcleece::byte_view&, unsigned char*, const unsigned char*)>& fun)
	{
		_mix = fun;
		return *this;
	}

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
		// there are 4 operations:
		// 1. compute nonce (from epk and _pk)
		// 2. write epk to ciphertext
		// 3. compute key (from esk and _pk)
		// 4. write crypto_secretbox(key) to ciphertext
		// #4 is changing (will be mixed with McEliece result. We also want the nonce back...

		unsigned char nonce[crypto_box_NONCEBYTES];
		unsigned char epk[crypto_box_PUBLICKEYBYTES];
		unsigned char esk[crypto_box_SECRETKEYBYTES];

		// ephemeral keypair
		if (crypto_box_keypair(epk, esk) != 0)
			return -1;

		// compute nonce
		compute_nonce(nonce, epk, _pk);

		// compute secret key
		// TODO: assert crypto_box_BEFORENMBYTES >= crypto_secretbox_KEYBYTES
		unsigned char k[crypto_box_BEFORENMBYTES];
		if (crypto_box_beforenm(k, _pk, esk) != 0)
			return -2;

		mcleece::byte_view output(c, mlen+crypto_box_PUBLICKEYBYTES); // TODO: this size is unknowable?
		output.write(epk, crypto_box_PUBLICKEYBYTES);

		if (_mix and !_mix(output, k, nonce))
			return -3;

		int ret = ::crypto_secretbox_easy(const_cast<unsigned char*>(output.data()), m, mlen, nonce, k);

		// TODO: zero out memory
		/*sodium_memzero(esk, sizeof esk);
		sodium_memzero(epk, sizeof epk);
		sodium_memzero(nonce, sizeof nonce);*/

		return ret;
	}

	int seal_open(unsigned char* m, const unsigned char* c, unsigned long long clen)
	{
		// 3 operations:
		// 1. compute nonce from c (epk and _pk)
		// 2. compute key from c (epk and _sk)
		// 3. decrypt with crypto_secretbox_open(key)

		if (_sk == nullptr)
			return -10;

		if (clen < crypto_box_SEALBYTES)
			return -9;
		if (clen < crypto_box_PUBLICKEYBYTES)
			return -8;

		mcleece::byte_view input(c, clen);

		// epk is at the start of c!!
		const unsigned char* epk = input.data();
		input.advance(crypto_box_PUBLICKEYBYTES);

		// compute nonce
		unsigned char nonce[crypto_box_NONCEBYTES];
		compute_nonce(nonce, epk, _pk);

		// TODO: assert crypto_box_PUBLICKEYBYTES < crypto_box_SEALBYTES ?

		// compute secret key
		unsigned char k[crypto_box_BEFORENMBYTES];
		if (crypto_box_beforenm(k, epk, _sk) != 0)
			return -7;

		if (_mix and !_mix(input, k, nonce))
			return -6;

		return ::crypto_secretbox_open_easy(m, input.data(), input.size(), nonce, k);
	}

protected:
	const unsigned char* _pk;
	const unsigned char* _sk;

	// data, nonce(24), key(32)
	std::function<bool(mcleece::byte_view&, unsigned char*, const unsigned char*)> _mix;
};

}
