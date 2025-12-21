#pragma once

#include <boost/asio.hpp>

#include <pb.h>
#include <pb_encode.h>
#include <pb_decode.h>

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace cypherock {

namespace detail {

inline void send_all(boost::asio::ip::tcp::socket &socket,
                     const uint8_t *data,
                     std::size_t len) {
    boost::asio::write(socket, boost::asio::buffer(data, len));
}

inline void recv_all(boost::asio::ip::tcp::socket &socket,
                     uint8_t *data,
                     std::size_t len) {
    boost::asio::read(socket, boost::asio::buffer(data, len));
}

// Write a 32-bit length prefix in big-endian
inline void write_u32_be(boost::asio::ip::tcp::socket &socket,
                         uint32_t value) {
    uint8_t buf[4];
    buf[0] = static_cast<uint8_t>((value >> 24) & 0xFF);
    buf[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
    buf[2] = static_cast<uint8_t>((value >> 8)  & 0xFF);
    buf[3] = static_cast<uint8_t>( value        & 0xFF);
    send_all(socket, buf, sizeof(buf));
}

// Read a 32-bit length prefix in big-endian
inline uint32_t read_u32_be(boost::asio::ip::tcp::socket &socket) {
    uint8_t buf[4];
    recv_all(socket, buf, sizeof(buf));
    return (static_cast<uint32_t>(buf[0]) << 24) |
           (static_cast<uint32_t>(buf[1]) << 16) |
           (static_cast<uint32_t>(buf[2]) << 8)  |
            static_cast<uint32_t>(buf[3]);
}

} // namespace detail

// ---- Send a nanopb message over TCP ----
// T is your message struct type (auth_AuthInitRequest, etc.)
template <typename T>
void send_pb_message(boost::asio::ip::tcp::socket &socket,
                     const pb_msgdesc_t *fields,
                     const T *msg_struct) {
    // Adjust if you expect bigger messages
    std::array<uint8_t, 512> buffer{};

    // Encode into the local buffer (length-delimited)
    pb_ostream_t stream =
        pb_ostream_from_buffer(buffer.data(), buffer.size());

    if (!pb_encode_delimited(&stream, fields, msg_struct)) {
        throw std::runtime_error(
            std::string("pb_encode_delimited failed: ") +
            PB_GET_ERROR(&stream));
    }

    uint32_t len = static_cast<uint32_t>(stream.bytes_written);

    // Send [4-byte length prefix] + [encoded message]
    detail::write_u32_be(socket, len);
    detail::send_all(socket, buffer.data(), len);
}

// ---- Receive a nanopb message over TCP ----
template <typename T>
void recv_pb_message(boost::asio::ip::tcp::socket &socket,
                     const pb_msgdesc_t *fields,
                     T *msg_struct) {
    // First read the 4-byte length prefix
    uint32_t len = detail::read_u32_be(socket);

    if (len == 0 || len > 1024 * 64) {
        throw std::runtime_error("Invalid incoming message length");
    }

    std::vector<uint8_t> buffer(len);
    detail::recv_all(socket, buffer.data(), buffer.size());

    pb_istream_t stream =
        pb_istream_from_buffer(buffer.data(), buffer.size());

    if (!pb_decode_delimited(&stream, fields, msg_struct)) {
        throw std::runtime_error(
            std::string("pb_decode_delimited failed: ") +
            PB_GET_ERROR(&stream));
    }
}

} // namespace cypherock
