cmake_minimum_required(VERSION 2.8)

set(SOURCES
	align.h
	brg_endian.h
	KeccakHash.c
	KeccakHash.h
	KeccakP-1600-reference.c
	KeccakP-1600-reference.h
	KeccakP-1600-SnP.h
	KeccakSponge-common.h
	KeccakSpongeWidth1600.c
	KeccakSpongeWidth1600.h
)

add_library(keccak STATIC ${SOURCES})

