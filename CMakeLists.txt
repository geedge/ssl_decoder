cmake_minimum_required (VERSION 3.0)

set(lib_name ssl_decoder)

project (${lib_name})

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include(Version)

set(CMAKE_MACOSX_RPATH 0)
set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -Wall)

find_program(CMAKE_CXX_CPPCHECK NAMES cppcheck)
if (CMAKE_CXX_CPPCHECK)
    list(
        APPEND CMAKE_CXX_CPPCHECK 
            "--enable=all"
            "--error-exitcode=1"
            "--suppress=unusedFunction"
            "--suppress=missingInclude"
            "--suppress=uselessAssignmentPtrArg"
            "--suppress=unmatchedSuppression"
            "--suppress=internalAstError"
            "--suppress=constParameter"
            "--suppress=variableScope"
            "--suppress=unreadVariable"
            "--suppress=unusedStructMember"
            "--suppress=noExplicitConstructor"
            "--suppress=*:${PROJECT_SOURCE_DIR}/deps/toml/*"
            "--suppress=*:${PROJECT_SOURCE_DIR}/deps/yyjson/*"
    )
    set(CMAKE_C_CPPCHECK ${CMAKE_CXX_CPPCHECK})
else()
  message(FATAL_ERROR "Could not find the program cppcheck.")
endif()


#for ASAN
set(ASAN_OPTION "OFF" CACHE STRING " set asan type chosen by the user, using OFF as default")
set_property(CACHE ASAN_OPTION  PROPERTY STRINGS OFF ADDRESS THREAD)
message(STATUS "ASAN_OPTION='${ASAN_OPTION}'")

if(ASAN_OPTION MATCHES "ADDRESS")
    set(CMAKE_C_FLAGS "${CMAKADDRESS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=address -fno-omit-frame-pointer")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=address -fno-omit-frame-pointer")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
elseif(ASAN_OPTION MATCHES "THREAD")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=thread -fno-omit-frame-pointer")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=thread -fno-omit-frame-pointer")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
endif()
# end of for ASAN

include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(/opt/MESA/include/)
include_directories(/opt/MESA/include/MESA/)
include_directories(/opt/tsg/framework/include/)

set(CMAKE_INSTALL_PREFIX /opt/tsg/)

enable_testing()
add_subdirectory(src) 
add_subdirectory(vendor)
add_subdirectory(test)

install(FILES bin/ssl_decoder.toml DESTINATION ${CMAKE_INSTALL_PREFIX}/sapp/etc/ssl/ COMPONENT PROFILE)
install(FILES bin/ssl_decoder_local_stat.sh DESTINATION ${CMAKE_INSTALL_PREFIX}/framework/bin/ COMPONENT PROFILE)
install(FILES include/ssl_decoder.h DESTINATION ${CMAKE_INSTALL_PREFIX}/include/decoder/ COMPONENT HEADER)

include(Package)
