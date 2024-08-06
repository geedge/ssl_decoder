add_definitions(-fPIC)

include_directories(/opt/MESA/include/)
include_directories(${PROJECT_SOURCE_DIR}/deps/)

aux_source_directory(${PROJECT_SOURCE_DIR}/deps/toml DEPS_SRC)
aux_source_directory(${PROJECT_SOURCE_DIR}/deps/yyjson DEPS_SRC)

set(SSL_DECODER_SRC ${DEPS_SRC} ssl_decoder.cpp ssl_export.cpp)

add_library(ssl_decoder SHARED ${SSL_DECODER_SRC})
set_target_properties(ssl_decoder PROPERTIES LINK_FLAGS "-Wl,--version-script=${PROJECT_SOURCE_DIR}/src/version.map")
target_link_libraries(ssl_decoder fieldstat4 -Wl,--no-whole-archive openssl-crypto-static -Wl,--no-whole-archive openssl-ssl-static)
set_target_properties(ssl_decoder PROPERTIES PREFIX "")

install(TARGETS ssl_decoder LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/sapp/stellar_plugin/ COMPONENT LIBRARIES)