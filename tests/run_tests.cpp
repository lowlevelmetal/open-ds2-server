/**
 * Open DS2 Server - Test Runner
 * 
 * Runs all unit tests for the Blaze protocol implementation
 */

#include "test_framework.hpp"

// Include test files
#include "test_tdf.cpp"
#include "test_blaze_codec.cpp"

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║       Open DS2 Server - Unit Test Suite                      ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";
    
    ds2::test::TestRunner runner;
    
    // =========================================================================
    // TDF Serialization Tests
    // =========================================================================
    runner.addTest("TDF_LabelEncode_Simple", test_TDF_LabelEncode_Simple);
    runner.addTest("TDF_LabelEncode_Short", test_TDF_LabelEncode_Short);
    runner.addTest("TDF_LabelEncode_AllChars", test_TDF_LabelEncode_AllChars);
    runner.addTest("TDF_Integer_Small", test_TDF_Integer_Small);
    runner.addTest("TDF_Integer_Negative", test_TDF_Integer_Negative);
    runner.addTest("TDF_Integer_Large", test_TDF_Integer_Large);
    runner.addTest("TDF_Integer_Zero", test_TDF_Integer_Zero);
    runner.addTest("TDF_String_Simple", test_TDF_String_Simple);
    runner.addTest("TDF_String_Empty", test_TDF_String_Empty);
    runner.addTest("TDF_String_Long", test_TDF_String_Long);
    runner.addTest("TDF_Blob_Simple", test_TDF_Blob_Simple);
    runner.addTest("TDF_Blob_Empty", test_TDF_Blob_Empty);
    runner.addTest("TDF_Struct_Simple", test_TDF_Struct_Simple);
    runner.addTest("TDF_List_Integers", test_TDF_List_Integers);
    runner.addTest("TDF_List_Strings", test_TDF_List_Strings);
    runner.addTest("TDF_Map_StringToInt", test_TDF_Map_StringToInt);
    runner.addTest("TDF_Complex_PlayerInfo", test_TDF_Complex_PlayerInfo);
    runner.addTest("TDF_MultipleFields", test_TDF_MultipleFields);
    
    // =========================================================================
    // Blaze Codec Tests
    // =========================================================================
    runner.addTest("BlazePacket_EncodeEmpty", test_BlazePacket_EncodeEmpty);
    runner.addTest("BlazePacket_EncodeWithPayload", test_BlazePacket_EncodeWithPayload);
    runner.addTest("BlazePacket_DecodeEmpty", test_BlazePacket_DecodeEmpty);
    runner.addTest("BlazePacket_Roundtrip", test_BlazePacket_Roundtrip);
    runner.addTest("BlazePacket_Reply", test_BlazePacket_Reply);
    runner.addTest("BlazePacket_ErrorReply", test_BlazePacket_ErrorReply);
    runner.addTest("BlazePacket_PartialHeader", test_BlazePacket_PartialHeader);
    runner.addTest("BlazePacket_PartialPayload", test_BlazePacket_PartialPayload);
    runner.addTest("ComponentId_Values", test_ComponentId_Values);
    
    // Run all tests
    return runner.run();
}
