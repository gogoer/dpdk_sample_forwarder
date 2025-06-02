cmake_minimum_required(VERSION 3.5)

project(dpdk_sample_forwarder LANGUAGES C)
set(CMAKE_C_STANDARD 99)

find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)

add_executable(dpdk_sample_forwarder main.c parser.c)

target_include_directories(dpdk_sample_forwarder PRIVATE ${DPDK_INCLUDE_DIRS})
target_link_libraries(dpdk_sample_forwarder ${DPDK_LIBRARIES})
target_compile_options(dpdk_sample_forwarder PRIVATE ${DPDK_CFLAGS_OTHER})

include(GNUInstallDirs)
install(TARGETS dpdk_sample_forwarder
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
