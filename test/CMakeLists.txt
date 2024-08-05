include_directories(${PROJECT_SOURCE_DIR}/deps/)
aux_source_directory(${PROJECT_SOURCE_DIR}/deps/toml DEPS_SRC)
aux_source_directory(${PROJECT_SOURCE_DIR}/deps/yyjson DEPS_SRC)

add_library(${PROJECT_NAME}_test_plug SHARED ssl_decoder_test.cpp ${DEPS_SRC})
add_dependencies(${PROJECT_NAME}_test_plug ${PROJECT_NAME})
target_link_libraries(${PROJECT_NAME}_test_plug cjson)
set_target_properties(${PROJECT_NAME}_test_plug  PROPERTIES PREFIX "")

add_executable(ssl_decoder_perf_test 
                    ssl_decoder_perf_main.cpp
                    ssl_decoder_perf_dummy.cpp
                    ${DEPS_SRC} ssl_decoder_test.cpp 
                    ${PROJECT_SOURCE_DIR}/src/ssl_decoder.cpp
                )

target_link_libraries(ssl_decoder_perf_test fieldstat4 pthread cjson -Wl,--no-whole-archive openssl-crypto-static -Wl,--no-whole-archive openssl-ssl-static)

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

# set_tests_properties(INSTALL_TEST_MAIN INSTALL_STELLAR UPDATE_SAPP_LOG COPY_CONFLIST COPY_INF COPY_TEST_MAIN COPY_SPEC UPDATE_PLUG_SO UPDATE_TEST_SO MKDIR_PLUG_CONF UPDATE_PLUG_CONF PROPERTIES FIXTURES_SETUP TestFixture)

# # run tests
# add_test(NAME MKDIR_METRICS COMMAND sh -c "mkdir -p ${TEST_RUN_DIR}/metrics/")
# add_test(NAME ssl_QUERY COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/query/query_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/query/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
# add_test(NAME ssl_CNAME COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/cname/cname_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/cname/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
# add_test(NAME ssl_NSEC_RR COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/nsec/nsec_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/nsec/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
# add_test(NAME ssl_NSEC_10_1_RR COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/nsec_10_1/nsec_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/nsec_10_1/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
# add_test(NAME ssl_NSEC3_RR COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/nsec3/nsec3_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/nsec3/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
# add_test(NAME ssl_PTR COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/ptr/ptr_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/ptr/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
# add_test(NAME ssl_SRV COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/srv/srv_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/srv/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
# add_test(NAME ssl_TXT COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/txt/txt_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/txt/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
# add_test(NAME ssl_HTTPS COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/https/https_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/https/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
# add_test(NAME ssl_CERT1 COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/cernet1/cernet1_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/cernet1/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
# add_test(NAME ssl_CERT2 COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/cernet2/cernet2_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/cernet2/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
# add_test(NAME ssl_SEC COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/sslsec/sslsec_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/sslsec/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
# add_test(NAME ssl_TCP_MULTI_TRANSCATION COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/multi_transcation/multi_transcation_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/multi_transcation/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
# add_test(NAME ssl_TCP_MULTI_PKT_TRANS_2BYTES COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/multi_pkt_trans_2bytes/multi_pkt_trans_2bytes_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/multi_pkt_trans_2bytes/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
# add_test(NAME ssl_TCP_LOST_PKT COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/tcp_lost_pkt/lost_pkt_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/tcp_lost_pkt/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
# add_test(NAME ssl_MULTI_SESSION COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/multi_session/multi_session_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/multi_session/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
# add_test(NAME ssl_NS_NSEC3_RRSIG_A_OPT COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/ns_nsec3_rrsig_a_opt/ns_nsec3_rrsig_a_opt_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/ns_nsec3_rrsig_a_opt/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})
# add_test(NAME ssl_PORT5353 COMMAND ${TEST_MAIN} ${CMAKE_CURRENT_SOURCE_DIR}/case/port5353/port5353_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/case/port5353/ -name *.pcap|sort -V" WORKING_DIRECTORY ${TEST_RUN_DIR})

# set_tests_properties(ssl_QUERY 
#                         ssl_CNAME 
#                         ssl_NSEC_RR 
#                         ssl_NSEC_10_1_RR
#                         ssl_NSEC3_RR 
#                         ssl_PTR 
#                         ssl_SRV
#                         ssl_TXT
#                         ssl_HTTPS
#                         ssl_CERT1
#                         ssl_CERT2
#                         ssl_SEC
#                         ssl_TCP_MULTI_TRANSCATION
#                         ssl_TCP_MULTI_PKT_TRANS_2BYTES
#                         ssl_TCP_LOST_PKT
#                         ssl_MULTI_SESSION
#                         ssl_NS_NSEC3_RRSIG_A_OPT
#                         ssl_PORT5353
#                         PROPERTIES FIXTURES_REQUIRED TestFixture
#                     )