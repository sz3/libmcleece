cmake_minimum_required(VERSION 3.10)

set(SOURCES
	b64_instream.h
	b64_outstream.h
	format.h
)

add_library(serialize INTERFACE)

add_subdirectory(test)

