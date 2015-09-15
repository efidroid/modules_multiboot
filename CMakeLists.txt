cmake_minimum_required(VERSION 2.8)

# common
project(multiboot)

set(CMAKE_BUILD_TYPE Release)
set(CMAKE_C_FLAGS "-Wall -Wextra -Werror -Wshadow -fPIC -static-libgcc -Wl,-static")

# main
add_executable(init
	main.c
)
