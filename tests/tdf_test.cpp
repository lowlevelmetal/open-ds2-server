#include <gtest/gtest.h>

#include <cstdint>
#include <initializer_list>
#include <limits>

#include "blaze/tdf.hpp"

using namespace opends2;

namespace {

Bytes bytes(std::initializer_list<unsigned> values) {
    Bytes out;
    for (const auto v : values) out.push_back(static_cast<std::byte>(v));
    return out;
}

Bytes field_header(tdf::Tag tag, tdf::Type type) {
    return bytes({(tag.raw() >> 16) & 0xFF, (tag.raw() >> 8) & 0xFF, tag.raw() & 0xFF, static_cast<unsigned>(type)});
}

std::int64_t round_trip_integer(std::int64_t value) {
    tdf::Writer w;
    w.integer("VAL", value);
    const auto top = tdf::decode(w.take());
    return std::get<std::int64_t>(top.find("VAL")->data);
}

}  // namespace

TEST(TdfTag, EncodesSixBitsPerCharacter) {
    EXPECT_EQ(tdf::Tag("A").raw(), 0x840000u);
    EXPECT_EQ(tdf::Tag("ADDR").raw(), 0x864932u);
}

TEST(TdfTag, LabelRoundTrips) {
    EXPECT_EQ(tdf::Tag("ADDR").label(), "ADDR");
    EXPECT_EQ(tdf::Tag("IP").label(), "IP");
    EXPECT_EQ(tdf::Tag::parse("PORT"), tdf::Tag("PORT"));
}

TEST(TdfTag, RejectsInvalidLabels) {
    EXPECT_THROW(tdf::Tag::parse("lower"), std::invalid_argument);
    EXPECT_THROW(tdf::Tag::parse("abcd"), std::invalid_argument);
    EXPECT_THROW(tdf::Tag::parse(""), std::invalid_argument);
}

TEST(TdfVarint, KnownEncodings) {
    tdf::Writer w;
    w.value_integer(0).value_integer(63).value_integer(64).value_integer(-1);
    EXPECT_EQ(w.take(), bytes({0x00, 0x3F, 0x80, 0x01, 0x41}));
}

TEST(TdfVarint, RoundTripsEdgeValues) {
    for (const std::int64_t v : {std::int64_t{0}, std::int64_t{1}, std::int64_t{63}, std::int64_t{64},
                                 std::int64_t{8191}, std::int64_t{8192}, std::int64_t{-1}, std::int64_t{-64},
                                 std::int64_t{0x7F000001}, std::numeric_limits<std::int64_t>::max(),
                                 std::numeric_limits<std::int64_t>::min() + 1}) {
        EXPECT_EQ(round_trip_integer(v), v) << v;
    }
}

TEST(TdfString, IncludesNulTerminatorInLength) {
    tdf::Writer w;
    w.value_string("abc");
    EXPECT_EQ(w.take(), bytes({0x04, 'a', 'b', 'c', 0x00}));
}

TEST(TdfDecode, ComplexMessageRoundTrips) {
    tdf::Writer w;
    w.begin_union("ADDR", 0x00)
        .begin_group("VALU")
        .string("HOST", "127.0.0.1")
        .integer("IP", 0x7F000001)
        .integer("PORT", 10041)
        .end_group();
    w.begin_list("LIST", tdf::Type::String, 2).value_string("one").value_string("two");
    w.begin_map("CONF", tdf::Type::String, tdf::Type::Integer, 1).value_string("key").value_integer(-5);
    w.begin_list("GRPS", tdf::Type::Group, 1).begin_group_value().integer("ID", 7).end_group();
    w.union_unset("NONE");
    w.pair("PAIR", 4, 1);
    w.triple("TRIP", 4, 1, 12345);
    w.float32("FLT", 1.5f);
    const std::int64_t ids[] = {1, 2, 3};
    w.int_list("IDS", ids);
    const Bytes encoded = w.take();

    const auto top = tdf::decode(encoded);
    ASSERT_EQ(top.fields.size(), 9u);

    const auto* addr = top.find("ADDR")->get_if<tdf::Union>();
    ASSERT_NE(addr, nullptr);
    ASSERT_EQ(addr->member.size(), 1u);
    const auto& valu = std::get<tdf::Group>(addr->member.front().value.data);
    EXPECT_EQ(std::get<std::string>(valu.find("HOST")->data), "127.0.0.1");
    EXPECT_EQ(std::get<std::int64_t>(valu.find("PORT")->data), 10041);

    EXPECT_EQ(top.find("NONE")->get_if<tdf::Union>()->key, tdf::kUnionUnset);
    EXPECT_EQ(std::get<float>(top.find("FLT")->data), 1.5f);
    EXPECT_EQ(std::get<tdf::IntList>(top.find("IDS")->data), (tdf::IntList{1, 2, 3}));

    // Re-encoding the decoded tree must reproduce the original bytes exactly.
    EXPECT_EQ(tdf::encode(top), encoded);
}

TEST(TdfDecode, PreservesGroupBaseMarker) {
    // "GRP" group starting with 0x02, containing VAL=1.
    tdf::Writer inner;
    inner.integer("VAL", 1);
    Bytes encoded = field_header("GRP", tdf::Type::Group);
    encoded.push_back(std::byte{0x02});
    const auto body = inner.take();
    encoded.insert(encoded.end(), body.begin(), body.end());
    encoded.push_back(std::byte{0x00});

    const auto top = tdf::decode(encoded);
    const auto& group = std::get<tdf::Group>(top.find("GRP")->data);
    EXPECT_TRUE(group.base_marker);
    EXPECT_EQ(group.fields.size(), 1u);
    EXPECT_EQ(tdf::encode(top), encoded);
}

TEST(TdfDecode, RejectsTruncatedInput) {
    tdf::Writer w;
    w.string("HOST", "example.com");
    auto encoded = w.take();
    encoded.pop_back();
    EXPECT_THROW(tdf::decode(encoded), DecodeError);
}

TEST(TdfDecode, RejectsOversizedCounts) {
    // List of integers claiming 1000 elements with no data behind it.
    Bytes encoded = field_header("LIST", tdf::Type::List);
    const auto rest = bytes({0x00, 0xA8, 0x0F});
    encoded.insert(encoded.end(), rest.begin(), rest.end());
    EXPECT_THROW(tdf::decode(encoded), DecodeError);
}

TEST(TdfDump, RendersNestedFields) {
    tdf::Writer w;
    w.begin_group("VALU").string("HOST", "h").end_group();
    const auto text = tdf::dump(tdf::decode(w.take()));
    EXPECT_NE(text.find("VALU: {"), std::string::npos);
    EXPECT_NE(text.find("  HOST: \"h\""), std::string::npos);
}

TEST(TdfWriter, DetectsUnbalancedGroups) {
    tdf::Writer w;
    w.begin_group("VALU");
    EXPECT_THROW(w.take(), std::logic_error);
    EXPECT_THROW(tdf::Writer{}.end_group(), std::logic_error);
}
