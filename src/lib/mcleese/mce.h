#pragma once

#include "public_key.h"
#include "secret_key.h"

#include "mceliece348864/crypto_kem.h"

namespace mcleese
{
	int generate_keypair(public_key& pk, secret_key& sk)
	{
		return crypto_kem_keypair(pk.pk(), sk.sk());
	}

}
