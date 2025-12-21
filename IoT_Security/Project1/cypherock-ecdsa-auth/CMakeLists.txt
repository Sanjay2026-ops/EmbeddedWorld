cmake_minimum_required(VERSION 3.10)
project(cypherock_ecdsa_auth C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

find_package(Boost REQUIRED COMPONENTS system)

include_directories(
    ${Boost_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/common
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/nanopb
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/trezor-crypto
)

# ---- Collect all trezor-crypto .c files ----
file(GLOB TREZOR_CRYPTO_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/trezor-crypto/*.c
)

# ❌ hume BIP32 / NEM nahi chahiye, inke through ed25519/curve25519 ki dependency aa rahi hai
list(FILTER TREZOR_CRYPTO_SOURCES EXCLUDE REGEX "bip32.c$")
list(FILTER TREZOR_CRYPTO_SOURCES EXCLUDE REGEX "nem.c$")

# ---- server ----
add_executable(server
    server/main.cpp
    common/auth.pb.c
    common/crypto_util.c

    third_party/nanopb/pb_common.c
    third_party/nanopb/pb_encode.c
    third_party/nanopb/pb_decode.c

    ${TREZOR_CRYPTO_SOURCES}
)

target_link_libraries(server PRIVATE Boost::system)

# ---- client ----
add_executable(client
    client/main.cpp
    common/auth.pb.c
    common/crypto_util.c

    third_party/nanopb/pb_common.c
    third_party/nanopb/pb_encode.c
    third_party/nanopb/pb_decode.c

    ${TREZOR_CRYPTO_SOURCES}
)

target_link_libraries(client PRIVATE Boost::system)
