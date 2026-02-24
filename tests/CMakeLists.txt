add_executable(tinyblake_tests
    test_blake2b.cpp
    test_blake2b_keyed.cpp
    test_hmac.cpp
    test_pbkdf2.cpp
    test_truncation.cpp
    test_params.cpp
    test_cpuid.cpp
)

target_link_libraries(tinyblake_tests PRIVATE tinyblake)
target_include_directories(tinyblake_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
set_target_properties(tinyblake_tests PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

# Warning flags for tests
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(tinyblake_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set_property(TARGET tinyblake_tests APPEND_STRING PROPERTY LINK_FLAGS
            " -Wl,-z,relro,-z,now -Wl,-z,noexecstack")
    endif()
    # macOS: -bind_at_load is deprecated on modern macOS (eager binding is the default)
    if(MINGW)
        set_property(TARGET tinyblake_tests APPEND_STRING PROPERTY LINK_FLAGS
            " -Wl,--nxcompat -Wl,--dynamicbase -Wl,--high-entropy-va")
    endif()
elseif(MSVC)
    target_compile_options(tinyblake_tests PRIVATE /W4 /WX)
    set_property(TARGET tinyblake_tests APPEND_STRING PROPERTY LINK_FLAGS
        " /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA")
endif()

add_test(NAME tinyblake_tests COMMAND tinyblake_tests)
