cmake_minimum_required(VERSION 3.22.1)

include(FetchContent)
FetchContent_Declare(
       Corrosion
       GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
       GIT_TAG v0.6 # Optionally specify a commit hash, version tag or branch here
   )
FetchContent_MakeAvailable(Corrosion)

project("vpn-dummy")

set( Rust_RUSTUP_INSTALL_MISSING_TARGET ON)
corrosion_import_crate( MANIFEST_PATH ${CMAKE_SOURCE_DIR}/../rust/Cargo.toml)

add_library(${CMAKE_PROJECT_NAME} SHARED
    dummy.cpp)


add_dependencies(${CMAKE_PROJECT_NAME} vpn)

target_link_libraries(${CMAKE_PROJECT_NAME}
    vpn
    android
    log)
