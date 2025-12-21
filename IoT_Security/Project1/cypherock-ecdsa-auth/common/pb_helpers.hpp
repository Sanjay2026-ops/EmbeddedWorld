#ifndef PB_HELPERS_HPP
#define PB_HELPERS_HPP

extern "C" {
#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"
}

#include <cstdint>
#include <cstring>
#include <string>

namespace pbhelpers {

/* Simple fixed-size byte buffer used with nanopb callbacks */
struct Bytes {
    uint8_t *buf;     // where to store / read bytes
    size_t   max_size; // capacity of buf
    size_t   size;     // actual data size
};

/* Encode callback for bytes/string fields */
inline bool encode_bytes_cb(pb_ostream_t *stream,
                            const pb_field_t *field,
                            void * const *arg)
{
    const Bytes *b = static_cast<const Bytes*>(*arg);
    if (!pb_encode_tag_for_field(stream, field)) {
        return false;
    }
    return pb_encode_string(stream, b->buf, b->size);
}

/* Decode callback for bytes/string fields */
inline bool decode_bytes_cb(pb_istream_t *stream,
                            const pb_field_t *field,
                            void **arg)
{
    Bytes *b = static_cast<Bytes*>(*arg);
    b->size = stream->bytes_left;

    if (b->size > b->max_size) {
        PB_SET_ERROR(stream, "bytes field too long");
        return false;
    }

    if (!pb_read(stream, b->buf, b->size)) {
        return false;
    }
    return true;
}

/* Helper to bind encode callback */
inline void set_bytes_field_for_encode(pb_callback_t &field, Bytes &b)
{
    field.funcs.encode = &encode_bytes_cb;
    field.arg = &b;
}

/* Helper to bind decode callback */
inline void set_bytes_field_for_decode(pb_callback_t &field, Bytes &b)
{
    field.funcs.decode = &decode_bytes_cb;
    field.arg = &b;
}

/* Utility: copy from std::string into Bytes */
inline void fill_bytes_from_string(Bytes &b, const std::string &s)
{
    b.size = s.size();
    if (b.size > b.max_size) {
        b.size = b.max_size;
    }
    std::memcpy(b.buf, s.data(), b.size);
}

/* Utility: bytes -> std::string (for logging) */
inline std::string bytes_to_string(const Bytes &b)
{
    return std::string(reinterpret_cast<const char*>(b.buf), b.size);
}

} // namespace pbhelpers

#endif // PB_HELPERS_HPP
