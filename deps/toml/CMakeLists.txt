set(CMAKE_C_FLAGS "-std=c99")
add_definitions(-fPIC)
add_library(toml STATIC toml.c)