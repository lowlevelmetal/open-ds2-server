#include "blaze/tdf.hpp"

#include <algorithm>
#include <bit>
#include <format>
#include <iterator>

namespace opends2::tdf {

namespace {

// Guards against stack exhaustion from hostile, deeply nested payloads.
constexpr int kMaxDepth = 64;

// --- Primitives -------------------------------------------------------------

// Varint layout: first byte = [continue:1][negative:1][low 6 bits];
// following bytes = [continue:1][next 7 bits]. Magnitude is stored, not two's complement.
std::int64_t read_varint(ByteReader& in) {
    std::uint8_t b = in.u8();
    const bool negative = (b & 0x40) != 0;
    std::uint64_t magnitude = b & 0x3Fu;
    unsigned shift = 6;
    while ((b & 0x80) != 0) {
        if (shift >= 64) throw DecodeError("varint too long");
        b = in.u8();
        magnitude |= static_cast<std::uint64_t>(b & 0x7Fu) << shift;
        shift += 7;
    }
    return static_cast<std::int64_t>(negative ? 0 - magnitude : magnitude);
}

void write_varint(ByteWriter& out, std::int64_t value) {
    std::uint64_t magnitude = value < 0 ? 0 - static_cast<std::uint64_t>(value) : static_cast<std::uint64_t>(value);
    std::uint8_t first = static_cast<std::uint8_t>(magnitude & 0x3F);
    if (value < 0) first |= 0x40;
    magnitude >>= 6;
    if (magnitude != 0) first |= 0x80;
    out.u8(first);
    while (magnitude != 0) {
        auto b = static_cast<std::uint8_t>(magnitude & 0x7F);
        magnitude >>= 7;
        if (magnitude != 0) b |= 0x80;
        out.u8(b);
    }
}

// Reads a length or element count. Every TDF value occupies at least one byte,
// so anything larger than the remaining input is malformed.
std::size_t read_count(ByteReader& in) {
    const auto n = read_varint(in);
    if (n < 0 || static_cast<std::uint64_t>(n) > in.remaining()) {
        throw DecodeError(std::format("invalid length/count {}", n));
    }
    return static_cast<std::size_t>(n);
}

Type read_type(ByteReader& in) {
    const auto t = in.u8();
    if (t > static_cast<std::uint8_t>(Type::Float)) {
        throw DecodeError(std::format("unknown TDF type 0x{:02x}", t));
    }
    return static_cast<Type>(t);
}

std::string read_string(ByteReader& in) {
    const auto length = read_count(in);
    const auto raw = in.bytes(length);
    std::string s(reinterpret_cast<const char*>(raw.data()), raw.size());
    if (!s.empty() && s.back() == '\0') s.pop_back();
    return s;
}

void write_string(ByteWriter& out, std::string_view s) {
    write_varint(out, static_cast<std::int64_t>(s.size() + 1));
    out.bytes(std::as_bytes(std::span(s)));
    out.u8(0);
}

void write_blob(ByteWriter& out, ByteView b) {
    write_varint(out, static_cast<std::int64_t>(b.size()));
    out.bytes(b);
}

void write_tag(ByteWriter& out, Tag tag, Type type) {
    out.u8(static_cast<std::uint8_t>(tag.raw() >> 16));
    out.u8(static_cast<std::uint8_t>(tag.raw() >> 8));
    out.u8(static_cast<std::uint8_t>(tag.raw()));
    out.u8(static_cast<std::uint8_t>(type));
}

// --- Decoding ---------------------------------------------------------------

Value read_value(ByteReader& in, Type type, int depth);

Field read_field(ByteReader& in, int depth) {
    const std::uint32_t b0 = in.u8();
    const std::uint32_t b1 = in.u8();
    const std::uint32_t b2 = in.u8();
    const auto tag = Tag::from_raw((b0 << 16) | (b1 << 8) | b2);
    const auto type = read_type(in);
    return Field{tag, read_value(in, type, depth)};
}

Group read_group(ByteReader& in, int depth) {
    Group group;
    if (in.peek_u8() == 0x02) {
        in.u8();
        group.base_marker = true;
    }
    while (in.peek_u8() != 0x00) {
        group.fields.push_back(read_field(in, depth + 1));
    }
    in.u8();  // terminator
    return group;
}

Value read_value(ByteReader& in, Type type, int depth) {
    if (depth > kMaxDepth) throw DecodeError("TDF nesting too deep");

    switch (type) {
        case Type::Integer:
            return {read_varint(in)};
        case Type::String:
            return {read_string(in)};
        case Type::Blob: {
            const auto raw = in.bytes(read_count(in));
            return {Bytes(raw.begin(), raw.end())};
        }
        case Type::Group:
            return {read_group(in, depth)};
        case Type::List: {
            List list;
            list.element_type = read_type(in);
            const auto count = read_count(in);
            list.items.reserve(count);
            for (std::size_t i = 0; i < count; ++i) {
                list.items.push_back(read_value(in, list.element_type, depth + 1));
            }
            return {std::move(list)};
        }
        case Type::Map: {
            Map map;
            map.key_type = read_type(in);
            map.value_type = read_type(in);
            const auto count = read_count(in);
            map.entries.reserve(count);
            for (std::size_t i = 0; i < count; ++i) {
                auto key = read_value(in, map.key_type, depth + 1);
                auto value = read_value(in, map.value_type, depth + 1);
                map.entries.push_back(MapEntry{std::move(key), std::move(value)});
            }
            return {std::move(map)};
        }
        case Type::Union: {
            Union u;
            u.key = in.u8();
            if (u.key != kUnionUnset) {
                u.member.push_back(read_field(in, depth + 1));
            }
            return {std::move(u)};
        }
        case Type::IntList: {
            IntList values;
            const auto count = read_count(in);
            values.reserve(count);
            for (std::size_t i = 0; i < count; ++i) {
                values.push_back(read_varint(in));
            }
            return {std::move(values)};
        }
        case Type::Pair: {
            Pair p;
            p.a = read_varint(in);
            p.b = read_varint(in);
            return {p};
        }
        case Type::Triple: {
            Triple t;
            t.a = read_varint(in);
            t.b = read_varint(in);
            t.c = read_varint(in);
            return {t};
        }
        case Type::Float:
            return {std::bit_cast<float>(in.u32())};
    }
    throw DecodeError("unreachable TDF type");
}

// --- Encoding ---------------------------------------------------------------

void write_value(ByteWriter& out, const Value& value);

void write_field(ByteWriter& out, const Field& field) {
    write_tag(out, field.tag, field.value.type());
    write_value(out, field.value);
}

void write_group_fields(ByteWriter& out, const Group& group) {
    for (const auto& f : group.fields) {
        write_field(out, f);
    }
}

void write_value(ByteWriter& out, const Value& value) {
    switch (value.type()) {
        case Type::Integer:
            write_varint(out, std::get<std::int64_t>(value.data));
            break;
        case Type::String:
            write_string(out, std::get<std::string>(value.data));
            break;
        case Type::Blob:
            write_blob(out, std::get<Bytes>(value.data));
            break;
        case Type::Group: {
            const auto& group = std::get<Group>(value.data);
            if (group.base_marker) out.u8(0x02);
            write_group_fields(out, group);
            out.u8(0x00);
            break;
        }
        case Type::List: {
            const auto& list = std::get<List>(value.data);
            out.u8(static_cast<std::uint8_t>(list.element_type));
            write_varint(out, static_cast<std::int64_t>(list.items.size()));
            for (const auto& item : list.items) write_value(out, item);
            break;
        }
        case Type::Map: {
            const auto& map = std::get<Map>(value.data);
            out.u8(static_cast<std::uint8_t>(map.key_type));
            out.u8(static_cast<std::uint8_t>(map.value_type));
            write_varint(out, static_cast<std::int64_t>(map.entries.size()));
            for (const auto& entry : map.entries) {
                write_value(out, entry.key);
                write_value(out, entry.value);
            }
            break;
        }
        case Type::Union: {
            const auto& u = std::get<Union>(value.data);
            out.u8(u.key);
            if (u.key != kUnionUnset && !u.member.empty()) write_field(out, u.member.front());
            break;
        }
        case Type::IntList: {
            const auto& values = std::get<IntList>(value.data);
            write_varint(out, static_cast<std::int64_t>(values.size()));
            for (const auto v : values) write_varint(out, v);
            break;
        }
        case Type::Pair: {
            const auto& p = std::get<Pair>(value.data);
            write_varint(out, p.a);
            write_varint(out, p.b);
            break;
        }
        case Type::Triple: {
            const auto& t = std::get<Triple>(value.data);
            write_varint(out, t.a);
            write_varint(out, t.b);
            write_varint(out, t.c);
            break;
        }
        case Type::Float:
            out.u32(std::bit_cast<std::uint32_t>(std::get<float>(value.data)));
            break;
    }
}

// --- Dumping ----------------------------------------------------------------

void dump_value(std::string& out, const Value& value, int indent);

void dump_fields(std::string& out, const std::vector<Field>& fields, int indent) {
    for (const auto& f : fields) {
        out.append(static_cast<std::size_t>(indent) * 2, ' ');
        std::format_to(std::back_inserter(out), "{}: ", f.tag.label());
        dump_value(out, f.value, indent);
        out += '\n';
    }
}

void close_block(std::string& out, int indent, char bracket) {
    out.append(static_cast<std::size_t>(indent) * 2, ' ');
    out += bracket;
}

void dump_value(std::string& out, const Value& value, int indent) {
    auto it = std::back_inserter(out);
    switch (value.type()) {
        case Type::Integer: {
            const auto v = std::get<std::int64_t>(value.data);
            if (v >= 0) {
                std::format_to(it, "{} (0x{:x})", v, v);
            } else {
                std::format_to(it, "{}", v);
            }
            break;
        }
        case Type::String:
            std::format_to(it, "{:?}", std::get<std::string>(value.data));
            break;
        case Type::Blob: {
            const auto& blob = std::get<Bytes>(value.data);
            std::format_to(it, "blob[{}]", blob.size());
            for (std::size_t i = 0; i < std::min<std::size_t>(blob.size(), 32); ++i) {
                std::format_to(it, " {:02x}", std::to_integer<unsigned>(blob[i]));
            }
            if (blob.size() > 32) out += " ...";
            break;
        }
        case Type::Group: {
            const auto& group = std::get<Group>(value.data);
            out += group.base_marker ? "{ (0x02)\n" : "{\n";
            dump_fields(out, group.fields, indent + 1);
            close_block(out, indent, '}');
            break;
        }
        case Type::List: {
            const auto& list = std::get<List>(value.data);
            std::format_to(it, "list<{}>[{}] [\n", to_string(list.element_type), list.items.size());
            for (const auto& item : list.items) {
                out.append(static_cast<std::size_t>(indent + 1) * 2, ' ');
                dump_value(out, item, indent + 1);
                out += '\n';
            }
            close_block(out, indent, ']');
            break;
        }
        case Type::Map: {
            const auto& map = std::get<Map>(value.data);
            std::format_to(it, "map<{}, {}>[{}] {{\n", to_string(map.key_type), to_string(map.value_type),
                           map.entries.size());
            for (const auto& entry : map.entries) {
                out.append(static_cast<std::size_t>(indent + 1) * 2, ' ');
                dump_value(out, entry.key, indent + 1);
                out += " => ";
                dump_value(out, entry.value, indent + 1);
                out += '\n';
            }
            close_block(out, indent, '}');
            break;
        }
        case Type::Union: {
            const auto& u = std::get<Union>(value.data);
            if (u.key == kUnionUnset || u.member.empty()) {
                out += "union(unset)";
            } else {
                std::format_to(it, "union(0x{:02x}) {{\n", u.key);
                dump_fields(out, u.member, indent + 1);
                close_block(out, indent, '}');
            }
            break;
        }
        case Type::IntList: {
            const auto& values = std::get<IntList>(value.data);
            out += '[';
            for (std::size_t i = 0; i < values.size(); ++i) {
                std::format_to(it, "{}{}", i == 0 ? "" : ", ", values[i]);
            }
            out += ']';
            break;
        }
        case Type::Pair: {
            const auto& p = std::get<Pair>(value.data);
            std::format_to(it, "pair({}, {})", p.a, p.b);
            break;
        }
        case Type::Triple: {
            const auto& t = std::get<Triple>(value.data);
            std::format_to(it, "triple({}, {}, {})", t.a, t.b, t.c);
            break;
        }
        case Type::Float:
            std::format_to(it, "{}f", std::get<float>(value.data));
            break;
    }
}

}  // namespace

// --- Public API -------------------------------------------------------------

std::string_view to_string(Type type) {
    switch (type) {
        case Type::Integer: return "integer";
        case Type::String: return "string";
        case Type::Blob: return "blob";
        case Type::Group: return "group";
        case Type::List: return "list";
        case Type::Map: return "map";
        case Type::Union: return "union";
        case Type::IntList: return "intlist";
        case Type::Pair: return "pair";
        case Type::Triple: return "triple";
        case Type::Float: return "float";
    }
    return "?";
}

std::string Tag::label() const {
    std::string s;
    for (int shift = 18; shift >= 0; shift -= 6) {
        s += static_cast<char>(((raw_ >> shift) & 0x3F) + 0x20);
    }
    while (!s.empty() && s.back() == ' ') s.pop_back();
    return s;
}

const Value* Group::find(Tag tag) const {
    const auto it = std::ranges::find(fields, tag, &Field::tag);
    return it == fields.end() ? nullptr : &it->value;
}

Group decode(ByteView payload) {
    ByteReader in(payload);
    Group top;
    while (!in.empty()) {
        top.fields.push_back(read_field(in, 0));
    }
    return top;
}

Bytes encode(const Group& top) {
    ByteWriter out;
    write_group_fields(out, top);
    return out.take();
}

std::string dump(const Group& top) {
    std::string out;
    dump_fields(out, top.fields, 0);
    return out;
}

// --- Writer -----------------------------------------------------------------

void Writer::header(Tag tag, Type type) { write_tag(out_, tag, type); }

Writer& Writer::integer(Tag tag, std::int64_t value) {
    header(tag, Type::Integer);
    write_varint(out_, value);
    return *this;
}

Writer& Writer::string(Tag tag, std::string_view value) {
    header(tag, Type::String);
    write_string(out_, value);
    return *this;
}

Writer& Writer::blob(Tag tag, ByteView value) {
    header(tag, Type::Blob);
    write_blob(out_, value);
    return *this;
}

Writer& Writer::float32(Tag tag, float value) {
    header(tag, Type::Float);
    out_.u32(std::bit_cast<std::uint32_t>(value));
    return *this;
}

Writer& Writer::pair(Tag tag, std::int64_t a, std::int64_t b) {
    header(tag, Type::Pair);
    write_varint(out_, a);
    write_varint(out_, b);
    return *this;
}

Writer& Writer::triple(Tag tag, std::int64_t a, std::int64_t b, std::int64_t c) {
    header(tag, Type::Triple);
    write_varint(out_, a);
    write_varint(out_, b);
    write_varint(out_, c);
    return *this;
}

Writer& Writer::int_list(Tag tag, std::span<const std::int64_t> values) {
    header(tag, Type::IntList);
    write_varint(out_, static_cast<std::int64_t>(values.size()));
    for (const auto v : values) write_varint(out_, v);
    return *this;
}

Writer& Writer::begin_group(Tag tag) {
    header(tag, Type::Group);
    ++open_groups_;
    return *this;
}

Writer& Writer::end_group() {
    if (open_groups_ == 0) throw std::logic_error("tdf::Writer::end_group without matching begin");
    out_.u8(0x00);
    --open_groups_;
    return *this;
}

Writer& Writer::begin_union(Tag tag, std::uint8_t key) {
    header(tag, Type::Union);
    out_.u8(key);
    return *this;
}

Writer& Writer::union_unset(Tag tag) { return begin_union(tag, kUnionUnset); }

Writer& Writer::begin_list(Tag tag, Type element_type, std::size_t count) {
    header(tag, Type::List);
    out_.u8(static_cast<std::uint8_t>(element_type));
    write_varint(out_, static_cast<std::int64_t>(count));
    return *this;
}

Writer& Writer::begin_map(Tag tag, Type key_type, Type value_type, std::size_t count) {
    header(tag, Type::Map);
    out_.u8(static_cast<std::uint8_t>(key_type));
    out_.u8(static_cast<std::uint8_t>(value_type));
    write_varint(out_, static_cast<std::int64_t>(count));
    return *this;
}

Writer& Writer::value_integer(std::int64_t value) {
    write_varint(out_, value);
    return *this;
}

Writer& Writer::value_string(std::string_view value) {
    write_string(out_, value);
    return *this;
}

Writer& Writer::begin_group_value() {
    ++open_groups_;
    return *this;
}

Writer& Writer::field(const Field& f) {
    write_field(out_, f);
    return *this;
}

Bytes Writer::take() {
    if (open_groups_ != 0) throw std::logic_error("tdf::Writer::take with unclosed groups");
    return out_.take();
}

}  // namespace opends2::tdf
