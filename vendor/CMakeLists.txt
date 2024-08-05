# CMakeFiles for 3rd vendor library

include(ExternalProject)

### OpenSSL 1.1.1m
ExternalProject_Add(openssl PREFIX openssl
        URL ${CMAKE_CURRENT_SOURCE_DIR}/openssl-1.1.1m.tar.gz
        URL_MD5 8ec70f665c145c3103f6e330f538a9db
        CONFIGURE_COMMAND ./Configure  linux-x86_64 --prefix=<INSTALL_DIR> --openssldir=<INSTALL_DIR>/lib/ssl -fPIC no-shared 
		BUILD_COMMAND ${MAKE_COMMAND}
		INSTALL_COMMAND make install_sw
        BUILD_IN_SOURCE 1)

ExternalProject_Get_Property(openssl INSTALL_DIR)
set(OPENSSL_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
set(OPENSSL_LINK_DIRECTORIES ${INSTALL_DIR}/lib)
set(OPENSSL_PKGCONFIG_PATH ${INSTALL_DIR}/lib/pkgconfig/)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(openssl-crypto-static STATIC IMPORTED GLOBAL)
add_dependencies(openssl-crypto-static openssl)
set_property(TARGET openssl-crypto-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libcrypto.a)
set_property(TARGET openssl-crypto-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)

add_library(openssl-ssl-static STATIC IMPORTED GLOBAL)
add_dependencies(openssl-ssl-static openssl)
set_property(TARGET openssl-ssl-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libssl.a)
set_property(TARGET openssl-ssl-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
