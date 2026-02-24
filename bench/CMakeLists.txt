add_executable(tinyblake_bench bench_all.cpp)
target_link_libraries(tinyblake_bench PRIVATE tinyblake)
target_include_directories(tinyblake_bench PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
set_target_properties(tinyblake_bench PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

# Warning flags for benchmarks
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(tinyblake_bench PRIVATE -Wall -Wextra -Wpedantic -Werror)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set_property(TARGET tinyblake_bench APPEND_STRING PROPERTY LINK_FLAGS
            " -Wl,-z,relro,-z,now -Wl,-z,noexecstack")
    endif()
    # macOS: -bind_at_load is deprecated on modern macOS (eager binding is the default)
    if(MINGW)
        set_property(TARGET tinyblake_bench APPEND_STRING PROPERTY LINK_FLAGS
            " -Wl,--nxcompat -Wl,--dynamicbase -Wl,--high-entropy-va")
    endif()
elseif(MSVC)
    target_compile_options(tinyblake_bench PRIVATE /W4 /WX)
    set_property(TARGET tinyblake_bench APPEND_STRING PROPERTY LINK_FLAGS
        " /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA")
endif()
