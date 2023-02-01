cmake_minimum_required(VERSION 3.7)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -march=native -mtune=native -Wall -Wno-unused-parameter -Wno-sign-compare -DKATNUM=10 \"-DCRYPTO_NAMESPACE(x)=x\" \"-D_CRYPTO_NAMESPACE(x)=_##x\"")

set(SOURCES
	benes.c
	bm.c
	controlbits.c
	decrypt.c
	encrypt.c
	fft.c
	fft_tr.c
	gf.c
	operations.c
	pk_gen.c
	sk_gen.c
	vec.c
)

add_library(mceliece6960119f STATIC ${SOURCES})

target_include_directories(mceliece6960119f PUBLIC
	.
	subroutines
)

