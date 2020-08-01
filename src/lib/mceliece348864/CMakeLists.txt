cmake_minimum_required(VERSION 2.8)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -march=native -mtune=native -Wall -DKATNUM=10")

set(SOURCES
	nist/kat_kem.c
	nist/rng.c
	nist/rng.h
	randombytes.h
	aes256ctr.c
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

add_library(mceliece348864 STATIC ${SOURCES})

