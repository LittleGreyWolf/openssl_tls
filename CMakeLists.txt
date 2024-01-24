cmake_minimum_required (VERSION 3.5)
project(openssl_tls)

IF(WIN32)
	set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/../bin)
ELSEIF(UNIX)
	set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/../bin/gcc_x64)
ENDIF()

include_directories(${PROJECT_SOURCE_DIR}/openssl/include)

if(MSVC)
	#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup")
endif()

IF(WIN32)
	set(PRO_OPENSSL_LIB ${PROJECT_SOURCE_DIR}/openssl/lib/vc_x86/libssl.lib ${PROJECT_SOURCE_DIR}/openssl/lib/vc_x86/libcrypto.lib)
ELSEIF(UNIX)
	set(PRO_OPENSSL_LIB ${PROJECT_SOURCE_DIR}/openssl/lib/gcc_x64/libcrypto.so.1.1 ${PROJECT_SOURCE_DIR}/openssl/lib/gcc_x64/libssl.so.1.1)	
ENDIF()

IF(UNIX)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wl,-rpath=.")
ENDIF()

ADD_EXECUTABLE(SSLServer ${PROJECT_SOURCE_DIR}/src/sslserver.cpp)
TARGET_LINK_LIBRARIES(SSLServer ${PRO_OPENSSL_LIB})

ADD_EXECUTABLE(SSLServerConcurrent ${PROJECT_SOURCE_DIR}/src/sslserver_concurrent.cpp)
TARGET_LINK_LIBRARIES(SSLServerConcurrent ${PRO_OPENSSL_LIB})

ADD_EXECUTABLE(SSLClient ${PROJECT_SOURCE_DIR}/src/sslclient.cpp)
TARGET_LINK_LIBRARIES(SSLClient ${PRO_OPENSSL_LIB})
