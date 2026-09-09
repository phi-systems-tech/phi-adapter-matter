cmake_minimum_required(VERSION 3.21)

project(phi-adapter-matter
    VERSION 0.0.4
    DESCRIPTION "Phi Matter controller adapter, built on connectedhomeip"
    LANGUAGES CXX
)

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

# The SDK comes from phi-chip-dev: one static library, the flags it was
# compiled with, and the PAA roots. No GN here, no checkout, no network.
find_package(phi-chip 1.5.1.0 CONFIG REQUIRED)

set(PHI_ADAPTER_SDK_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../phi-adapter-sdk" CACHE PATH
    "Path to local phi-adapter-sdk checkout. If not found, find_package(phi-adapter-sdk) is used."
)
option(PHI_ADAPTER_MATTER_USE_LOCAL_ADAPTER_SDK
    "Use local ../phi-adapter-sdk checkout when available"
    ON
)

if(NOT TARGET phi::adapter-sdk)
    if(PHI_ADAPTER_MATTER_USE_LOCAL_ADAPTER_SDK AND EXISTS "${PHI_ADAPTER_SDK_SOURCE_DIR}/CMakeLists.txt")
        message(STATUS "Using local phi-adapter-sdk from: ${PHI_ADAPTER_SDK_SOURCE_DIR}")
        add_subdirectory("${PHI_ADAPTER_SDK_SOURCE_DIR}" "${CMAKE_BINARY_DIR}/_deps/phi-adapter-sdk" EXCLUDE_FROM_ALL)
    else()
        message(STATUS "Using installed phi-adapter-sdk via find_package")
        find_package(phi-adapter-sdk CONFIG REQUIRED)
    endif()
endif()
if(NOT TARGET phi::adapter-sdk)
    message(FATAL_ERROR "phi-adapter-sdk target phi::adapter-sdk not found")
endif()

add_executable(phi_adapter_matter_ipc
    src/controller.cpp
    src/main.cpp
    src/thread.cpp
)

target_include_directories(phi_adapter_matter_ipc
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# What the SDK build does and the sidecar keeps: dead code goes, and every
# function is its own section so the linker can drop it.
target_compile_options(phi_adapter_matter_ipc PRIVATE
    -ffunction-sections
    -fdata-sections
    -fno-strict-aliasing
)
target_link_options(phi_adapter_matter_ipc PRIVATE
    -Wl,--gc-sections
    -Wl,--as-needed
)

target_link_libraries(phi_adapter_matter_ipc
    PRIVATE
        phi::chip
        phi::adapter-sdk
)

# The Matter SDK (phi::chip) is built with CHIPoBLE enabled, but phi-chip
# keeps that define private to its own platform target and does not export
# it. BLE commissioning here calls BLEMgrImpl(), which the platform headers
# only declare under CHIP_DEVICE_CONFIG_ENABLE_CHIPOBLE, so the adapter has
# to compile with the same view of BLE as the library it links against.
target_compile_definitions(phi_adapter_matter_ipc PRIVATE
    CHIP_DEVICE_CONFIG_ENABLE_CHIPOBLE=1
    CONFIG_NETWORK_LAYER_BLE=1
)

set_target_properties(phi_adapter_matter_ipc PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/plugins/adapters"
    INSTALL_RPATH "$ORIGIN"
)

install(TARGETS phi_adapter_matter_ipc
    RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/phi/plugins/adapters
)

install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/matter-config.json
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/phi/plugins/adapters
)

# The PAA roots devices attest against: the SDK package's production set,
# copied so the adapter's package stands on its own at runtime.
install(DIRECTORY ${PHI_CHIP_PAA_ROOT_CERTS_DIR}/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/phi/matter/paa-root-certs
    FILES_MATCHING PATTERN "*.der"
)
