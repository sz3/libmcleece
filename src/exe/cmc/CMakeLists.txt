cmake_minimum_required(VERSION 3.10)

project(cmc)

set (SOURCES
	main.cpp
)

add_executable (
	cmc
	${SOURCES}
)

target_link_libraries(cmc

	mceliece348864

	crypto
	keccak
	sodium
	ssl
)


