#pragma once

#include "public_key.h"
#include "private_key.h"

#include "mceliece348864/crypto_kem.h"

namespace mcleese
{
	int generate_keypair(public_key& pubk, private_key& secret)
	{
		return crypto_kem_keypair(pubk.data(), secret.data());
	}

	int generate_keypair(std::string pubk_path, std::string secret_path)
	{
		public_key pubk;
		private_key secret;
		int res = generate_keypair(pubk, secret);
		if (res != 0)
			return res;

		pubk.save(pubk_path);
		secret.save(secret_path);
	}

}
