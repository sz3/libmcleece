
#include "mceliece348864/crypto_kem.h"
#include <iostream>
#include <fstream>
#include <vector>
using std::vector;

namespace {
	void write(std::string filename, const vector<unsigned char>& contents)
	{
		std::ofstream of(filename);
		of.write(reinterpret_cast<const char*>(contents.data()), contents.size());
	}
}

int main()
{
// pk, sk
	vector<unsigned char> pk(crypto_kem_mceliece348864_ref_PUBLICKEYBYTES, 0);
	vector<unsigned char> sk(crypto_kem_mceliece348864_ref_SECRETKEYBYTES, 0);
	int res = crypto_kem_keypair(pk.data(), sk.data());
	std::cout << "hello" << res << std::endl;

	write("/tmp/test.pk", pk);
	write("/tmp/test.sk", sk);


	return 0;
}
