cmake_minimum_required(VERSION 2.8)

set(SOURCES
	Keccak-readable-and-compact.c
	SimpleFIPS202.h
)

add_library(keccak STATIC ${SOURCES})

