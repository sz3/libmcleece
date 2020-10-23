cmake_minimum_required(VERSION 3.10)

add_subdirectory(test)

set(SOURCES
	mcleece.cpp
	mcleece.h

	actions.h
	keygen.h
	message.h
	nonce.h
	private_key.h
	public_key.h
	session_key.h
)

add_library(mcleece_static STATIC ${SOURCES})
add_library(mcleece SHARED ${SOURCES})
set_target_properties(mcleece PROPERTIES PUBLIC_HEADER mcleece.h)

target_link_libraries(mcleece_static

	mceliece8192128

	getline
	keccak

	crypto
	sodium
	ssl
)

target_link_libraries(mcleece

	mceliece8192128

	getline
	keccak
)

install(
	TARGETS mcleece
	DESTINATION bin
)

