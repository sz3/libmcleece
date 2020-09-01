cmake_minimum_required(VERSION 3.10)

set(SOURCES
	get_line.c
	get_line.h
	helpers.c
	helpers.h
)

add_library(getline STATIC ${SOURCES})

