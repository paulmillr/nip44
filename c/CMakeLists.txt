# Copyright (c) 2024 Vaughn Nugent
# See the LICENSE in this directory for terms of use
#
# This file configures noscrypt with best defaults as possible while offering 
# some freedom in terms of crypto libraries if desired. Some defaults and 
# worst case fallback functions are defined and will get better as time goes on
# 

cmake_minimum_required (VERSION 3.10)

project(
	noscrypt
	LANGUAGES C
	DESCRIPTION "A compact, C90 cross-platform, cryptography library built specifically for nostr"
	HOMEPAGE_URL "https://www.vaughnnugent.com/resources/software/modules/noscrypt"	
)
set(_NC_PROJ_NAME "noscrypt")

option(NC_BUILD_TESTS "Build tests" OFF)
option(NC_ENABLE_UTILS "Enables the sidecar utility library" OFF)
option(NC_DISABLE_INPUT_VALIDATION "Disables public function input validation" OFF)
option(NC_FETCH_MBEDTLS "Fetch Mbed-TLS from it's source repository locally" OFF)
option(NC_FETCH_SECP256K1 "Fetch and locally build secp256k1 source code" ON)
option(NC_INCLUDE_MONOCYPHER "Statically link to vendored monocypher library" ON)
set(CRYPTO_LIB "" CACHE STRING "The crypto library to link to (mbedtls, openssl, bcrypt)")
set(CRYPTO_LIB_DIR "" CACHE STRING "The path to the crypto library if it's not globally available")
set(SECP256K1_LIB_DIR "" CACHE STRING "An optional path to search for the secp256k1 library if not globally installed")

string(TOLOWER ${CMAKE_BUILD_TYPE} build_type)

#list of noscrypt project defitnions
set(NC_PROJ_DEFINTIONS "")

include(FetchContent)

if(NC_FETCH_SECP256K1)

	#Fetch libsecp256k1, and build a minimal static library 
	set(SECP256K1_BUILD_BENCHMARK OFF)
	set(SECP256K1_BUILD_TESTS OFF)
	set(SECP256K1_BUILD_EXAMPLES OFF)
	set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF)
	set(SECP256K1_ENABLE_MODULE_ECDH ON)
	set(SECP256K1_ENABLE_MODULE_RECOVERY OFF)
	set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON)
	set(SECP256K1_ENABLE_MODULE_EXTRAKEYS ON)
	set(SECP256K1_ENABLE_MODULE_ELLSWIFT OFF)
	set(SECP256K1_INSTALL OFF)
	set(SECP256K1_DISABLE_SHARED ON)			#disales shared library output

	FetchContent_Declare(
	  libsecp256k1
	  GIT_REPOSITORY		https://github.com/bitcoin-core/secp256k1
	  GIT_TAG				642c885b6102725e25623738529895a95addc4f4 # release-0.5.1
	  GIT_PROGRESS			TRUE
	)

	FetchContent_MakeAvailable(libsecp256k1)
	
	#Must force FPIC when using secp256k1, ld linker complains otherwise
	set_target_properties(
		secp256k1 
		secp256k1_precomputed 
		
		PROPERTIES 
		POSITION_INDEPENDENT_CODE  ON
	)
	
else()	

	#search for an existing library, it's a required dependency
	find_library(secp256k1
		NAMES secp256k1 libsecp256k1 
		PATHS ${SECP256K1_LIB_DIR}
		REQUIRED
	)

endif()

#-----------------------------
#		MAIN PROJECT
#-----------------------------

set(NOSCRYPT_SRCS 
	"src/noscrypt.c"	
	"src/hkdf.c"
	"src/nc-crypto.c"				#pulls in c impl files as needed
)

set(NOSCRYPT_HEADERS
	"include/noscrypt.h"
	"include/platform.h"
	"src/nc-util.h"
	"src/hkdf.h"
	"src/nc-crypto.h"
)

#if utils are enabled, add the source files
if(NC_ENABLE_UTILS)
	list(APPEND NOSCRYPT_SRCS "src/noscryptutil.c")
	list(APPEND NOSCRYPT_HEADERS "include/noscryptutil.h")

	#notify the project that utils are enabled
	list(APPEND NC_PROJ_DEFINTIONS NC_ENABLE_UTILS)

	message(STATUS "Utilities libraries are enabled")
endif()

#static/shared library
add_library(${_NC_PROJ_NAME} SHARED ${NOSCRYPT_SRCS} ${NOSCRYPT_HEADERS})
add_library(${_NC_PROJ_NAME}_static STATIC ${NOSCRYPT_SRCS} ${NOSCRYPT_HEADERS})
set_target_properties(${_NC_PROJ_NAME} PROPERTIES POSITION_INDEPENDENT_CODE ON)		#fPIC for shared library

#set specific cmake commands to target our projects only
set_target_properties(
	${_NC_PROJ_NAME} 
	${_NC_PROJ_NAME}_static 
	
	#Setup the compiler options for c90 standard
	PROPERTIES 
	C_STANDARD 90
	C_STANDARD_REQUIRED ON
	C_EXTENSIONS ON			#enables c++ style comments (only required for mbedtls stuff)
)

target_compile_features(${_NC_PROJ_NAME} PRIVATE c_std_90)	#force compiler to use c90 standard for library
target_compile_features(${_NC_PROJ_NAME}_static PRIVATE c_std_90)	#force compiler to use c90 standard for library

target_include_directories(${_NC_PROJ_NAME} PRIVATE include)
target_include_directories(${_NC_PROJ_NAME}_static PRIVATE include)

#link libsecp256k1
target_link_libraries(${_NC_PROJ_NAME} PRIVATE secp256k1)
target_link_libraries(${_NC_PROJ_NAME}_static PRIVATE secp256k1)

#include secp256k1 headers
target_include_directories(${_NC_PROJ_NAME} SYSTEM PUBLIC vendor/secp256k1/include)
target_include_directories(${_NC_PROJ_NAME}_static SYSTEM PUBLIC vendor/secp256k1/include)

#############################################
#
#		Configure crypto library linking
#
#############################################

#Include mbedtls if enabled
if(NC_FETCH_MBEDTLS)

	###############
	# NOTE: Must disable shared libraries to avoid linking errors when using mbedtls
	###############
	set(BUILD_SHARED_LIBS OFF)

	set(ENABLE_PROGRAMS OFF)
	set(ENABLE_TESTING OFF)
	set(USE_SHARED_MBEDTLS_LIBRARY OFF)
	set(USE_STATIC_MBEDTLS_LIBRARY ON)
	set(DISABLE_PACKAGE_CONFIG_AND_INSTALL OFF)
	set(MBEDTLS_CONFIG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/vendor/mbedtls/mbedtls_noscrypt_config.h" CACHE STRING "" FORCE)

	FetchContent_Declare(
	  libmbedtls
	  GIT_REPOSITORY        https://github.com/Mbed-TLS/mbedtls.git
	  GIT_TAG               v3.6.0
	  GIT_PROGRESS          TRUE
	)

	FetchContent_MakeAvailable(libmbedtls)

	set(CRYPTO_LIB "mbedtls")		#enable linking to mbedtls

endif()

#try to load openssl quietly in order to check for its availability
find_package(OpenSSL QUIET)

#setup default linking to crypto libraries for certain plaftorms. 
#Windows defaults to bcrypt, openssl otherwise if installed
if(CRYPTO_LIB STREQUAL "")	
  if(MSVC)
	set(CRYPTO_LIB "bcrypt")
  elseif(OPENSSL_FOUND)
	set(CRYPTO_LIB "openssl")
  endif()

  message(STATUS "No crypto library was specified, defaulting to ${CRYPTO_LIB}")
endif()


#if mbedtls linking is enabled target the library
if(CRYPTO_LIB STREQUAL "mbedtls")

	message(STATUS "Linking to MbedTLS crypto library")

	#include mbedtls headers
	target_include_directories(${_NC_PROJ_NAME} SYSTEM PUBLIC vendor/mbedtls/include)
	target_include_directories(${_NC_PROJ_NAME}_static SYSTEM PUBLIC vendor/mbedtls/include)

	if(NC_FETCH_MBEDTLS)
		#link to included mbedtls
		target_link_libraries(${_NC_PROJ_NAME} PRIVATE mbedcrypto PRIVATE mbedtls)
		target_link_libraries(${_NC_PROJ_NAME}_static PRIVATE mbedcrypto PRIVATE mbedtls)
	else()
		#find the library
		find_library(MBEDTLS_LIB_CRYPTO
			NAMES mbedcrypto libmbedcrypto 
			PATHS ${CRYPTO_LIB_DIR}
		)
		
		find_library(MBEDTLS_LIB_TLS
			NAMES mbedtls libmbedtls
			PATHS ${CRYPTO_LIB_DIR}
		)

		message(STATUS "Found mbedtls crypto library at ${MBEDTLS_LIB_CRYPTO}")
		message(STATUS "Found mbedtls tls library at ${MBEDTLS_LIB_TLS}")

		#link to the library
		target_link_libraries(${_NC_PROJ_NAME} PRIVATE ${MBEDTLS_LIB_CRYPTO} PRIVATE ${MBEDTLS_LIB_TLS})
		target_link_libraries(${_NC_PROJ_NAME}_static PRIVATE ${MBEDTLS_LIB_CRYPTO} PRIVATE ${MBEDTLS_LIB_TLS})
	endif()

	#enable mbedtls crypto library bindings
	list(APPEND NC_PROJ_DEFINTIONS MBEDTLS_CRYPTO_LIB)

elseif(CRYPTO_LIB STREQUAL "openssl")

	set(OPENSSL_USE_STATIC_LIBS ON)
	find_package(OpenSSL REQUIRED)

	#include openssl headers
	target_include_directories(${_NC_PROJ_NAME} SYSTEM PUBLIC vendor/openssl/include)
	target_include_directories(${_NC_PROJ_NAME}_static SYSTEM PUBLIC vendor/openssl/include)

	#link to openssl
	message(STATUS "Linking to OpenSSL crypto library")
	target_link_libraries(${_NC_PROJ_NAME} PRIVATE OpenSSL::Crypto)
	target_link_libraries(${_NC_PROJ_NAME}_static PRIVATE OpenSSL::Crypto)

	#enable openssl crypto library bindings
	list(APPEND NC_PROJ_DEFINTIONS OPENSSL_CRYPTO_LIB)

elseif(CRYPTO_LIB STREQUAL "bcrypt")

	if(MSVC)
		#link bcrypt for Windows platforms
		target_link_libraries(${_NC_PROJ_NAME} PRIVATE "bcrypt.lib")
		target_link_libraries(${_NC_PROJ_NAME}_static PRIVATE "bcrypt.lib")
	else()
		message(FATAL_ERROR "Bcrypt is only supported on Windows platforms")
	endif()

else()

	message(FATAL_ERROR "You must select a supported cryptography library: openssl, mbedtls, or bcrypt (Windows only)")

endif()

add_compile_definitions($<$<CONFIG:Debug>:DEBUG>)
add_compile_definitions(NOSCRYPT_EXPORTING)			#enable exporting symbols

if(NC_DISABLE_INPUT_VALIDATION)
	list(APPEND NC_PROJ_DEFINTIONS NC_INPUT_VALIDATION_OFF)
endif()

set(_NC_COMPILE_OPTS)

#setup flags for windows compilation
if(MSVC)

   list(APPEND _NC_COMPILE_OPTS
		/sdl						#enable additional security checks
		/TC							#compile as c
		/GS							#buffer security check
		
		$<$<CONFIG:Debug>:/FC>				#show full path in diagnostics
		$<$<CONFIG:Debug>:/showIncludes>	#show a list of all included header files during build
		
		$<$<CONFIG:Debug>:/wd4820>	#disable warnings for struct padding and spectre mitigation wuen WX is enabled
		$<$<CONFIG:Debug>:/wd5045>	#disable warnings for spectre mitigation insertion

		#for debug configs
		$<$<CONFIG:Debug>:/options:strict>
		$<$<CONFIG:Debug>:/Wall>	#enable all warnings
		$<$<CONFIG:Debug>:/WX>		#warnings as errors (only for our project)
		$<$<CONFIG:Debug>:/Zi>		#enable rich debug info
		$<$<CONFIG:Debug>:/Zo>
   )

	#set build macros
	list(APPEND NC_PROJ_DEFINTIONS
		$<$<CONFIG:DEBUG>:DEBUG>
		$<$<CONFIG:RELEASE>:RELEASE>
	)

#configure gcc flags
elseif(CMAKE_COMPILER_IS_GNUCC)

	list(APPEND _NC_COMPILE_OPTS 
		-Wextra 
		-fstack-protector
	)

	#if debug build enable additional debug flags
	if(build_type STREQUAL "debug")
		 list(APPEND _NC_COMPILE_OPTS
		
			-g
			-Og
			-Wall
			-Werror
			-pedantic
		)
	endif()
endif()

target_compile_options(${_NC_PROJ_NAME} PRIVATE ${_NC_COMPILE_OPTS})
target_compile_options(${_NC_PROJ_NAME}_static PRIVATE ${_NC_COMPILE_OPTS})

#############################################
#
#	Build/link monocypher 
#
#############################################

# Monocypher only provides a few fallback functions
# for builds that don't use a more complete library
# implementation. Specifically cha-cha20 and secure 
# erase functions.

if(NC_INCLUDE_MONOCYPHER)

	#add monocypher as a static dep to the project
	add_library(monocypher STATIC 
		"vendor/monocypher/monocypher.c"
		"vendor/monocypher/monocypher.h"
	)

	target_link_libraries(${_NC_PROJ_NAME} PRIVATE monocypher)
	target_link_libraries(${_NC_PROJ_NAME}_static PRIVATE monocypher)

	#share mc header with project
	target_include_directories(monocypher SYSTEM PUBLIC vendor/monocypher)
	
	target_compile_features(monocypher PRIVATE c_std_99)			#targets c99

	if(MSVC)		
		target_compile_options(monocypher PRIVATE
			/sdl						#enable additional security checks
			/TC							#compile as c
			/GS							#buffer security check
		)

		#enable monocypher crypto library bindings
		list(APPEND NC_PROJ_DEFINTIONS NC_ENABLE_MONOCYPHER)

	elseif(CMAKE_COMPILER_IS_GNUCC)
		#from monocypher's Makefile
		target_compile_options(monocypher PRIVATE -pedantic -Wall -Wextra -O3 -march=native)

		#enable monocypher crypto library bindings
		list(APPEND NC_PROJ_DEFINTIONS NC_ENABLE_MONOCYPHER)
	else()
		message(WARNING "Monocypher is not supported on this platform")
	endif()
endif()

#Set NC variables to both projects
target_compile_definitions(${_NC_PROJ_NAME} PRIVATE ${NC_PROJ_DEFINTIONS})
target_compile_definitions(${_NC_PROJ_NAME}_static PRIVATE ${NC_PROJ_DEFINTIONS})

############################
#
#		TESTS
#
###########################
if(NC_BUILD_TESTS)

	#add test executable and link to shared library for more realistic usage
	add_executable(nctest tests/test.c)
	target_link_libraries(nctest ${_NC_PROJ_NAME})

	target_include_directories(nctest PRIVATE include)
	target_include_directories(nctest PRIVATE src)	#allow access to internal headers

	#enable c11 for testing
	target_compile_features(nctest PRIVATE c_std_11)
	target_compile_definitions(nctest PRIVATE ${NC_PROJ_DEFINTIONS})

	enable_testing()

	add_test(
		NAME nctest 
		COMMAND nctest
		CONFIGURATIONS ${CMAKE_BUILD_TYPE}
	)

endif()

###########################
#
#		Installing
#
###########################

#export shared library
install(TARGETS ${_NC_PROJ_NAME} 
	EXPORT MyLibraryTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

#export static library
install(TARGETS ${_NC_PROJ_NAME}_static
	EXPORT MyLibraryTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

SET(NC_INSTALL_HEADERS 
	include/noscrypt.h	#static install headers
	include/platform.h
)

if(NC_ENABLE_UTILS)
	LIST(APPEND 
		NC_INSTALL_HEADERS
		include/noscryptutil.h
	)
endif()

install(FILES 
	${NC_INSTALL_HEADERS}
	DESTINATION noscrypt
)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()