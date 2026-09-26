project(lws-api-test-dnssec-chain C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-dnssec-chain)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_SYS_ASYNC_DNS 1 requirements)
require_lws_config(LWS_WITH_SYS_ASYNC_DNS_DNSSEC 1 requirements)
require_lws_config(LWS_WITH_GENCRYPTO 1 requirements)
require_lws_config(LWS_WITH_IPV4 1 requirements)

# the fake nameserver is a plain BSD socket of the test's own
if (WIN32)
	set(requirements 0)
endif()

if (requirements)
	add_executable(${SAMP} ${SRCS})

	add_test(NAME api-test-dnssec-chain COMMAND lws-api-test-dnssec-chain)
	set_tests_properties(api-test-dnssec-chain
			     PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			     TIMEOUT 60)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
