project(lws-api-test-log-spew C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(CheckIncludeFile)
include(LwsCheckRequirements)

set(requirements 1)
# the spew under test is made of notice logs
require_lws_config(LWS_WITH_NO_LOGS 0 requirements)

if (requirements)

	add_executable(${PROJECT_NAME} main.c)
	add_test(NAME api-test-log-spew COMMAND lws-api-test-log-spew)

	# with pthreads, it also spews from several threads at once
	set(PTHREAD_LIB "")
	CHECK_INCLUDE_FILE(pthread.h LWS_HAVE_PTHREAD_H)
	if (LWS_HAVE_PTHREAD_H)
		if (WIN32)
			set(PTHREAD_LIB ${LWS_EXT_PTHREAD_LIBRARIES})
		elseif (NOT ${CMAKE_SYSTEM_NAME} MATCHES "QNX")
			set(PTHREAD_LIB pthread)
		endif()
	endif()

	if (websockets_shared)
		target_link_libraries(${PROJECT_NAME} websockets_shared ${PTHREAD_LIB} ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${PROJECT_NAME} websockets_shared)
	else()
		target_link_libraries(${PROJECT_NAME} websockets ${PTHREAD_LIB} ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
