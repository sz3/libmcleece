cmake_minimum_required(VERSION 3.7)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -march=native -mtune=native -Wall -DKATNUM=10 \"-DCRYPTO_NAMESPACE(x)=x\" \"-D_CRYPTO_NAMESPACE(x)=_##x\"")

set(SOURCES
	randombytes.h
	benes.c
	bm.c
	controlbits.c
	decrypt.c
	encrypt.c
	gf.c
	operations.c
	pk_gen.c
	root.c
	sk_gen.c
	synd.c
	transpose.c
	util.c
)

add_library(mceliece6960119f STATIC ${SOURCES})

