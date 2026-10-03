#pragma once

// TDF ("Tag Data Format") is the binary encoding used by EA's Blaze backend.
//
// The format implemented here follows the Blaze 3 layout documented by community
// projects for Mass Effect 3 and Battlefield 3, Dead Space 2's contemporaries.
// It has NOT yet been verified against Dead Space 2 traffic. See docs/PROTOCOL.md.
//
// Wire layout of a field: 3-byte tag, 1-byte type, then the type-specific value.

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "core/byte_io.hpp"

namespace opends2::tdf {

enum class Type : std::uint8_t {
    Integer = 0x00,  // variable-length signed integer
    String = 0x01,   // varint length (incl. NUL) + bytes + NUL
    Blob = 0x02,     // varint length + bytes
    Group = 0x03,    // nested fields terminated by 0x00
    List = 0x04,     // element type + varint count + values
    Map = 0x05,      // key type + value type + varint count + pairs
    Union = 0x06,    // 1-byte key; unless 0x7F, followed by one full field
    IntList = 0x07,  // varint count + varints
    Pair = 0x08,     // two varints (a.k.a. ObjectType)
    Triple = 0x09,   // three varints (a.k.a. ObjectId)
    Float = 0x0A,    // 4-byte big-endian IEEE 754
};

std::string_view to_string(Type type);

inline constexpr std::uint8_t kUnionUnset = 0x7F;

// A field label of up to four characters from the range 0x20-0x5F (upper-case
// letters, digits, space), packed six bits per character into 24 bits.
class Tag {
public:
    // Implicit compile-time conversion from a literal, so you can write
    // `writer.integer("PORT", 1234)`. Invalid labels fail to compile.
    template <std::size_t N>
    consteval Tag(const char (&label)[N]) : raw_(encode(std::string_view(label, N - 1))) {}

    static constexpr Tag from_raw(std::uint32_t raw) { return Tag(raw & 0xFFFFFF, Raw{}); }

    // Runtime counterpart of the literal constructor. Throws std::invalid_argument.
    static constexpr Tag parse(std::string_view label) { return Tag(encode(label), Raw{}); }

    constexpr std::uint32_t raw() const { return raw_; }
    std::string label() const;

    friend constexpr bool operator==(Tag, Tag) = default;

private:
    struct Raw {};
    constexpr Tag(std::uint32_t raw, Raw) : raw_(raw) {}

    static constexpr std::uint32_t encode(std::string_view label) {
        if (label.empty() || label.size() > 4) {
            throw std::invalid_argument("TDF tag must be 1-4 characters");
        }
        std::uint32_t raw = 0;
        for (std::size_t i = 0; i < 4; ++i) {
            const char c = i < label.size() ? label[i] : ' ';
            if (c < 0x20 || c > 0x5F) {
                throw std::invalid_argument("TDF tag characters must be in 0x20-0x5F (use upper-case)");
            }
            raw |= static_cast<std::uint32_t>(c - 0x20) << (18 - 6 * i);
        }
        return raw;
    }

    std::uint32_t raw_;
};

// ---------------------------------------------------------------------------
// Generic decoded tree. Useful for logging unknown packets and for handlers
// that only need to pull out a few fields.
// ---------------------------------------------------------------------------

struct Value;
struct Field;
struct MapEntry;

struct Group {
    std::vector<Field> fields;
    // Some Blaze 3 groups start with a 0x02 byte before their first field. Its
    // meaning is unconfirmed; it is preserved so re-encoding is lossless.
    bool base_marker = false;

    // First field with the given tag, or nullptr.
    const Value* find(Tag tag) const;
};

struct List {
    Type element_type = Type::Integer;
    std::vector<Value> items;
};

struct Map {
    Type key_type = Type::String;
    Type value_type = Type::String;
    std::vector<MapEntry> entries;
};

struct Union {
    std::uint8_t key = kUnionUnset;
    std::vector<Field> member;  // empty when unset, otherwise exactly one field
};

struct Pair {
    std::int64_t a = 0;
    std::int64_t b = 0;
};

struct Triple {
    std::int64_t a = 0;
    std::int64_t b = 0;
    std::int64_t c = 0;
};

using IntList = std::vector<std::int64_t>;

struct Value {
    // Alternative order matches the numeric Type values.
    std::variant<std::int64_t, std::string, Bytes, Group, List, Map, Union, IntList, Pair, Triple, float> data;

    Type type() const { return static_cast<Type>(data.index()); }

    template <class T>
    const T* get_if() const { return std::get_if<T>(&data); }
};

struct Field {
    Tag tag;
    Value value;
};

struct MapEntry {
    Value key;
    Value value;
};

// Decodes a packet payload: a sequence of fields running to the end of the buffer.
// Throws DecodeError on malformed input.
Group decode(ByteView payload);

// Encodes a decoded tree back into a packet payload.
Bytes encode(const Group& top);

// Human-readable, indented rendering of a decoded tree.
std::string dump(const Group& top);

// ---------------------------------------------------------------------------
// Streaming encoder for building responses.
//
//   tdf::Writer w;
//   w.begin_group("VALU").string("HOST", host).integer("PORT", port).end_group();
//   Bytes payload = w.take();
// ---------------------------------------------------------------------------

class Writer {
public:
    Writer& integer(Tag tag, std::int64_t value);
    Writer& boolean(Tag tag, bool value) { return integer(tag, value ? 1 : 0); }
    Writer& string(Tag tag, std::string_view value);
    Writer& blob(Tag tag, ByteView value);
    Writer& float32(Tag tag, float value);
    Writer& pair(Tag tag, std::int64_t a, std::int64_t b);
    Writer& triple(Tag tag, std::int64_t a, std::int64_t b, std::int64_t c);
    Writer& int_list(Tag tag, std::span<const std::int64_t> values);

    Writer& begin_group(Tag tag);
    Writer& end_group();

    // Must be followed by exactly one field write (the union's active member).
    Writer& begin_union(Tag tag, std::uint8_t key);
    Writer& union_unset(Tag tag);

    // Must be followed by `count` untagged values (value_* / begin_group_value).
    Writer& begin_list(Tag tag, Type element_type, std::size_t count);
    // Must be followed by `count` key/value pairs of untagged values.
    Writer& begin_map(Tag tag, Type key_type, Type value_type, std::size_t count);

    // Untagged values, for list elements and map keys/values.
    Writer& value_integer(std::int64_t value);
    Writer& value_string(std::string_view value);
    Writer& begin_group_value();  // close with end_group()

    // Writes a previously decoded field verbatim.
    Writer& field(const Field& field);

    // Returns the encoded payload and resets the writer.
    Bytes take();

private:
    void header(Tag tag, Type type);

    ByteWriter out_;
    int open_groups_ = 0;
};

}  // namespace opends2::tdf
