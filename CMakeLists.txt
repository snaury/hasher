project(hasher C CXX)
cmake_minimum_required(VERSION 2.8)

if(MSVC)
    # Workaround for Visual Studio 2012
    add_definitions(-D_VARIADIC_MAX=10)
endif(MSVC)
if(MINGW OR UNIX)
    add_definitions(-std=c++11 -Wall -Wno-deprecated -pthread)
endif()

#
# Find required boost libraries
#
if(WIN32)
    set(Boost_USE_STATIC_LIBS ON)
endif()
find_package(Boost REQUIRED COMPONENTS system thread timer chrono)

#
# Common settings for all executables
#
if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0501)
    if(MSVC)
        add_definitions(-DBOOST_ALL_NO_LIB=1)
    endif(MSVC)
endif(WIN32)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIR})

#
# Crypto++ files
#
if(MSVC)
    # It's easier to build a part of Crypto++ ourselves
    # So it's possible to just unpack sources into ext/cryptopp
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/ext)
    set(CRYPTOPP_SRC_FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/ext/cryptopp/cryptlib.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/ext/cryptopp/misc.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/ext/cryptopp/queue.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/ext/cryptopp/mqueue.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/ext/cryptopp/algparam.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/ext/cryptopp/filters.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/ext/cryptopp/fips140.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/ext/cryptopp/cpu.cpp

        ${CMAKE_CURRENT_SOURCE_DIR}/ext/cryptopp/iterhash.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/ext/cryptopp/md5.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/ext/cryptopp/sha.cpp
    )
else()
    set(CRYPTOPP_LIB_FILES cryptopp)
endif()

#
# Main executable
#
file(GLOB SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
add_executable(${PROJECT_NAME} ${SRC_FILES} ${CRYPTOPP_SRC_FILES})
target_link_libraries(${PROJECT_NAME} ${Boost_LIBRARIES} ${CRYPTOPP_LIB_FILES})
