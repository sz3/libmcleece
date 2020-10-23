cmake_minimum_required(VERSION 3.10)

set(SOURCES
	api.cpp
	api.h

	actions.h
	keygen.h
	message.h
	nonce.h
	private_key.h
	public_key.h
	session_key.h
)

add_library(mcleece STATIC ${SOURCES})

add_subdirectory(test)
