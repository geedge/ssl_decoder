include_directories(${PROJECT_SOURCE_DIR}/deps/)
aux_source_directory(${PROJECT_SOURCE_DIR}/deps/toml DEPS_SRC)
aux_source_directory(${PROJECT_SOURCE_DIR}/deps/yyjson DEPS_SRC)

add_library(${PROJECT_NAME}_test_plug SHARED ssl_decoder_test.cpp ${DEPS_SRC})
add_dependencies(${PROJECT_NAME}_test_plug ${PROJECT_NAME})
target_link_libraries(${PROJECT_NAME}_test_plug cjson -Wl,--no-whole-archive openssl-crypto-static -Wl,--no-whole-archive openssl-ssl-static)
set_target_properties(${PROJECT_NAME}_test_plug  PROPERTIES PREFIX "")

add_executable(ssl_decoder_perf_test 
                    ssl_decoder_perf_main.cpp
                    ssl_decoder_perf_dummy.cpp
                    ${DEPS_SRC} ssl_decoder_test.cpp 
                    ${PROJECT_SOURCE_DIR}/src/ssl_decoder.cpp
                    ${PROJECT_SOURCE_DIR}/src/ssl_export.cpp
                )

target_link_libraries(ssl_decoder_perf_test fieldstat4 pthread cjson -Wl,--no-whole-archive openssl-crypto-static -Wl,--no-whole-archive openssl-ssl-static -ldl)

set(TEST_RUN_DIR ${CMAKE_CURRENT_BINARY_DIR}/sapp)
set(TEST_MAIN ${TEST_RUN_DIR}/plugin_test_main)


# copy perf main
add_test(NAME MKDIR_PERF COMMAND sh -c "mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/perf/ ${CMAKE_CURRENT_BINARY_DIR}/perf/etc/ssl/")
add_test(NAME COPY_PERF_TEST_MAIN COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/test/ssl_decoder_perf_test ${CMAKE_CURRENT_BINARY_DIR}/perf")
add_test(NAME COPY_PERF_TEST_CONF COMMAND sh -c "cp ${PROJECT_SOURCE_DIR}/bin/${PROJECT_NAME}.toml ${CMAKE_CURRENT_BINARY_DIR}/perf/etc/ssl/${PROJECT_NAME}.toml")

# assemble test env
add_test(NAME UNINSTALL_TEST_MAIN COMMAND sh -c "rpm -qa sapp | grep -v not | xargs -i rpm -e {} --nodeps")
add_test(NAME INSTALL_TEST_MAIN COMMAND sh -c "rpm -i ${CMAKE_CURRENT_SOURCE_DIR}/env/sapp-4.3.59.c5b96a4-1.el8.x86_64.rpm --prefix=${CMAKE_CURRENT_BINARY_DIR}/sapp --force --nodeps")
add_test(NAME UNINSTALL_STELLAR COMMAND sh -c "rpm -qa stellar-on-sapp | grep -v not | xargs -i rpm -e {} --nodeps")
add_test(NAME INSTALL_STELLAR COMMAND sh -c "rpm -i ${CMAKE_CURRENT_SOURCE_DIR}/env/stellar-on-sapp-2.1.2.20b65ae-1.el8.x86_64.rpm --prefix=${CMAKE_CURRENT_BINARY_DIR}/ --force --nodeps")

add_test(NAME COPY_TEST_MAIN COMMAND sh -c "cp ${TEST_RUN_DIR}/tools/plugin_test_main ${TEST_RUN_DIR}/plugin_test_main")
add_test(NAME COPY_SPEC COMMAND sh -c "cp ${CMAKE_CURRENT_SOURCE_DIR}/env/spec.toml ${TEST_RUN_DIR}/stellar_plugin/spec.toml")
add_test(NAME COPY_CONFLIST COMMAND sh -c "cp ${CMAKE_CURRENT_SOURCE_DIR}/env/conflist.inf ${TEST_RUN_DIR}/plug/conflist.inf")
add_test(NAME COPY_INF COMMAND sh -c "cp ${CMAKE_CURRENT_SOURCE_DIR}/env/start_loader.inf ${TEST_RUN_DIR}/plug/stellar_on_sapp/start_loader.inf")

# update config files
add_test(NAME UPDATE_SAPP_LOG COMMAND bash -c "sed -i 's/sapp_log.fatal/sapp_log.info/' ${TEST_RUN_DIR}/etc/sapp_log.conf")
add_test(NAME UPDATE_SAPP_SYN_MODE COMMAND bash -c "sed -i 's/syn_mandatory=1/syn_mandatory=0/' ${TEST_RUN_DIR}/etc/sapp.toml")     
add_test(NAME UPDATE_SAPP_REORDER COMMAND bash -c "sed -i 's/reorder_pkt_max=32/reorder_pkt_max=5/' ${TEST_RUN_DIR}/etc/sapp.toml")

# update plugin to be tested
add_test(NAME UPDATE_PLUG_SO COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/src/${PROJECT_NAME}.so ${TEST_RUN_DIR}/stellar_plugin/${PROJECT_NAME}.so")
add_test(NAME UPDATE_TEST_SO COMMAND sh -c "cp ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}_test_plug.so ${TEST_RUN_DIR}/stellar_plugin/${PROJECT_NAME}_test_plug.so")
add_test(NAME MKDIR_PLUG_CONF COMMAND sh -c "mkdir -p ${TEST_RUN_DIR}/etc/ssl/")
add_test(NAME UPDATE_PLUG_CONF COMMAND sh -c "cp ${PROJECT_SOURCE_DIR}/bin/${PROJECT_NAME}.toml ${TEST_RUN_DIR}/etc/ssl/${PROJECT_NAME}.toml")

set_tests_properties(INSTALL_TEST_MAIN INSTALL_STELLAR UPDATE_SAPP_LOG COPY_CONFLIST COPY_INF COPY_TEST_MAIN COPY_SPEC UPDATE_PLUG_SO UPDATE_TEST_SO MKDIR_PLUG_CONF UPDATE_PLUG_CONF PROPERTIES FIXTURES_SETUP TestFixture)

# # run tests
add_test(NAME RUN_SSL_TEST COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/ssl/ssl_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/ssl -name '*.pcap' | sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
add_test(NAME RUN_E21_BUG_E21_TEST COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/e21/ssl_e21_target_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/e21/ -name '*.pcap' | sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
add_test(NAME RUN_E21_BUG_XXG_TEST COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/xxg/ssl_xxg_target_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/xxg/ -name '*.pcap' | sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
add_test(NAME RUN_BUG_TEST COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/bug/ssl_bug_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/bug/ -name '*.pcap' | sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
add_test(NAME RUN_MULTIPLE_HANDSHAKE_TEST COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/multiple_handshake/ssl_multiple_handshake_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/multiple_handshake/ -name '*.pcap' | sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
add_test(NAME RUN_CLOSE_CONTAINS_PAYLOAD_TEST COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/close_contains_payload/ssl_close_contains_payload_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/close_contains_payload/ -name '*.pcap' | sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
add_test(NAME RUN_EXTENSION_EXCEED_16 COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/extensions_exceed_16/extensions_exceed_16_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/extensions_exceed_16/ -name '*.pcap' | sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
add_test(NAME RUN_CLIENT_HELLO_FRAGMENT1 COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/client_hello_fragment1/ssl_client_hello_fragment_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/client_hello_fragment1/ -name '*.pcap' | sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
add_test(NAME RUN_CLIENT_HELLO_FRAGMENT2 COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/client_hello_fragment2/ssl_client_hello_fragment_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/client_hello_fragment2/ -name '*.pcap' | sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
add_test(NAME RUN_CLIENT_HELLO_FRAGMENT3 COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/client_hello_fragment3/ssl_client_hello_fragment_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/client_hello_fragment3/ -name '*.pcap' | sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
add_test(NAME RUN_ACK_CONTAINS_PAYLOAD COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/tcp_ack_contians_payload/ssl_tcp_ack_contians_payload_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/tcp_ack_contians_payload/ -name '*.pcap' | sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})

set_tests_properties(RUN_SSL_TEST 
                        RUN_E21_BUG_E21_TEST 
                        RUN_E21_BUG_XXG_TEST 
                        RUN_BUG_TEST
                        RUN_MULTIPLE_HANDSHAKE_TEST 
                        RUN_CLOSE_CONTAINS_PAYLOAD_TEST 
                        RUN_EXTENSION_EXCEED_16
                        RUN_CLIENT_HELLO_FRAGMENT1
                        RUN_CLIENT_HELLO_FRAGMENT2
                        RUN_CLIENT_HELLO_FRAGMENT3
                        RUN_ACK_CONTAINS_PAYLOAD
                        PROPERTIES FIXTURES_REQUIRED TestFixture
                    )