cmake_minimum_required(VERSION 3.10)

set(SOURCES
	actions.h
	init_rng.h
	keygen.h
	message.h
	nonce.h
	private_key.h
	public_key.h
	session_key.h
)

add_library(mcleece INTERFACE)

add_subdirectory(test)
