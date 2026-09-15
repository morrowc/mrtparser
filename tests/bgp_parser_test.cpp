#include "bgp_parser.h"
#include <arpa/inet.h>
#include <cstring>
#include <gtest/gtest.h>
#include <vector>

TEST(BgpParserTest, ParseMessage) {
  bgp::BgpHeader header;
  std::vector<uint8_t> payload;

  // Size < 19
  std::vector<uint8_t> smallBuf(18, 0xFF);
  EXPECT_FALSE(bgp::BgpParser::parseMessage(smallBuf.data(), smallBuf.size(),
                                            header, payload));

  // Header length > size
  std::vector<uint8_t> lenTooBig(25, 0xFF);
  uint16_t fakeLen = htons(50);
  std::memcpy(lenTooBig.data() + 16, &fakeLen, 2);
  lenTooBig[18] = static_cast<uint8_t>(bgp::BgpMessageType::KEEPALIVE);
  EXPECT_FALSE(bgp::BgpParser::parseMessage(lenTooBig.data(), lenTooBig.size(),
                                            header, payload));

  // Valid message (Keepalive, 19 bytes)
  std::vector<uint8_t> validKeepalive(19, 0xFF);
  uint16_t keepaliveLen = htons(19);
  std::memcpy(validKeepalive.data() + 16, &keepaliveLen, 2);
  validKeepalive[18] = static_cast<uint8_t>(bgp::BgpMessageType::KEEPALIVE);
  EXPECT_TRUE(bgp::BgpParser::parseMessage(
      validKeepalive.data(), validKeepalive.size(), header, payload));
  EXPECT_EQ(header.length, 19);
  EXPECT_EQ(header.type, bgp::BgpMessageType::KEEPALIVE);
  EXPECT_TRUE(payload.empty());

  // Valid message with payload
  std::vector<uint8_t> msgWithPayload(23, 0xFF);
  uint16_t fullLen = htons(23);
  std::memcpy(msgWithPayload.data() + 16, &fullLen, 2);
  msgWithPayload[18] = static_cast<uint8_t>(bgp::BgpMessageType::NOTIFICATION);
  msgWithPayload[19] = 1;
  msgWithPayload[20] = 2;
  msgWithPayload[21] = 3;
  msgWithPayload[22] = 4;
  EXPECT_TRUE(bgp::BgpParser::parseMessage(
      msgWithPayload.data(), msgWithPayload.size(), header, payload));
  EXPECT_EQ(header.length, 23);
  EXPECT_EQ(header.type, bgp::BgpMessageType::NOTIFICATION);
  ASSERT_EQ(payload.size(), 4);
  EXPECT_EQ(payload[0], 1);
  EXPECT_EQ(payload[3], 4);
}

TEST(BgpParserTest, ParseAttributes) {
  std::vector<bgp::BgpAttribute> attrs;

  // Empty buffer
  EXPECT_TRUE(bgp::BgpParser::parseAttributes(nullptr, 0, attrs));
  EXPECT_TRUE(attrs.empty());

  // Truncated buffer (less than 2 bytes for flags + type)
  std::vector<uint8_t> truncBuf = {0x40};
  EXPECT_FALSE(
      bgp::BgpParser::parseAttributes(truncBuf.data(), truncBuf.size(), attrs));

  // Truncated non-extended length (no len byte)
  std::vector<uint8_t> noLenBuf = {0x40, 0x01};
  EXPECT_FALSE(
      bgp::BgpParser::parseAttributes(noLenBuf.data(), noLenBuf.size(), attrs));

  // Truncated value
  std::vector<uint8_t> valTooShort = {0x40, 0x01, 0x05, 0x01, 0x02};
  EXPECT_FALSE(bgp::BgpParser::parseAttributes(valTooShort.data(),
                                               valTooShort.size(), attrs));

  // Truncated extended length (needs 2 bytes for len, only 1 provided)
  std::vector<uint8_t> truncExtLen = {0x50, 0x02, 0x00};
  EXPECT_FALSE(bgp::BgpParser::parseAttributes(truncExtLen.data(),
                                               truncExtLen.size(), attrs));

  // Truncated extended value
  std::vector<uint8_t> extValTooShort = {0x50, 0x02, 0x00, 0x04, 0x01, 0x02};
  EXPECT_FALSE(bgp::BgpParser::parseAttributes(extValTooShort.data(),
                                               extValTooShort.size(), attrs));

  // Valid standard and extended attributes
  std::vector<uint8_t> validBuf = {
      // Standard attribute: ORIGIN (type 1), flags:
      // optional(0x80)|transitive(0x40)|partial(0x20)
      0xE0, 0x01, 0x01, 0x00,
      // Extended attribute: AS_PATH (type 2), flags: extended_length(0x10)
      0x10, 0x02, 0x00, 0x02, 0xAA, 0xBB};
  EXPECT_TRUE(
      bgp::BgpParser::parseAttributes(validBuf.data(), validBuf.size(), attrs));
  ASSERT_EQ(attrs.size(), 2);
  EXPECT_TRUE(attrs[0].flags.optional);
  EXPECT_TRUE(attrs[0].flags.transitive);
  EXPECT_TRUE(attrs[0].flags.partial);
  EXPECT_FALSE(attrs[0].flags.extended_length);
  EXPECT_EQ(attrs[0].type, bgp::BgpAttributeType::ORIGIN);
  ASSERT_EQ(attrs[0].value.size(), 1);
  EXPECT_EQ(attrs[0].value[0], 0x00);

  EXPECT_FALSE(attrs[1].flags.optional);
  EXPECT_FALSE(attrs[1].flags.transitive);
  EXPECT_FALSE(attrs[1].flags.partial);
  EXPECT_TRUE(attrs[1].flags.extended_length);
  EXPECT_EQ(attrs[1].type, bgp::BgpAttributeType::AS_PATH);
  ASSERT_EQ(attrs[1].value.size(), 2);
  EXPECT_EQ(attrs[1].value[0], 0xAA);
  EXPECT_EQ(attrs[1].value[1], 0xBB);
}

TEST(BgpParserTest, ParsePrefixes) {
  std::vector<bgp::BgpPrefix> prefixes;

  // Empty buffer
  EXPECT_TRUE(bgp::BgpParser::parsePrefixes(nullptr, 0, prefixes));
  EXPECT_TRUE(prefixes.empty());

  // Buffer truncated before length byte
  std::vector<uint8_t> empty;
  EXPECT_TRUE(bgp::BgpParser::parsePrefixes(empty.data(), 0, prefixes));

  // Prefix length 24 but only 2 bytes of IP
  std::vector<uint8_t> truncPrefix = {24, 192, 0};
  EXPECT_FALSE(bgp::BgpParser::parsePrefixes(truncPrefix.data(),
                                             truncPrefix.size(), prefixes));

  // Valid IPv4 prefixes of various lengths
  std::vector<uint8_t> validPrefixes = {
      0,                  // 0.0.0.0/0 (0 bytes)
      8,  10,             // 10.0.0.0/8 (1 byte)
      24, 192, 168, 1,    // 192.168.1.0/24 (3 bytes)
      32, 1,   2,   3, 4  // 1.2.3.4/32 (4 bytes)
  };
  EXPECT_TRUE(bgp::BgpParser::parsePrefixes(
      validPrefixes.data(), validPrefixes.size(), prefixes, false));
  ASSERT_EQ(prefixes.size(), 4);
  EXPECT_EQ(prefixes[0].length, 0);
  EXPECT_EQ(prefixes[0].prefix.size(), 0);
  EXPECT_EQ(prefixes[1].length, 8);
  EXPECT_EQ(prefixes[1].prefix.size(), 1);
  EXPECT_EQ(prefixes[2].length, 24);
  EXPECT_EQ(prefixes[2].prefix.size(), 3);
  EXPECT_EQ(prefixes[3].length, 32);
  EXPECT_EQ(prefixes[3].prefix.size(), 4);

  // Add-path prefix truncated path_id
  std::vector<uint8_t> truncAddPath = {0x00, 0x00, 0x01};
  prefixes.clear();
  EXPECT_FALSE(bgp::BgpParser::parsePrefixes(
      truncAddPath.data(), truncAddPath.size(), prefixes, true));

  // Valid Add-path prefix
  std::vector<uint8_t> validAddPath = {
      0x00, 0x00, 0x00, 0x0A,  // path_id = 10
      24,   10,   20,   30     // 10.20.30.0/24
  };
  EXPECT_TRUE(bgp::BgpParser::parsePrefixes(
      validAddPath.data(), validAddPath.size(), prefixes, true));
  ASSERT_EQ(prefixes.size(), 1);
  EXPECT_TRUE(prefixes[0].has_path_id);
  EXPECT_EQ(prefixes[0].path_id, 10);
  EXPECT_EQ(prefixes[0].length, 24);
  ASSERT_EQ(prefixes[0].prefix.size(), 3);
}

TEST(BgpParserTest, ParseOpen) {
  bgp::BgpOpenMessage open;

  // Payload too small (< 10 bytes)
  std::vector<uint8_t> smallPayload(9, 0);
  EXPECT_FALSE(bgp::BgpParser::parseOpen(smallPayload.data(),
                                         smallPayload.size(), open));

  // Opt params len too large
  std::vector<uint8_t> optTooLarge = {
      4,                 // version
      0xFD, 0xE9,        // my_as = 65001
      0x00, 0xB4,        // hold_time = 180
      1,    2,    3, 4,  // bgp_id = 1.2.3.4
      10                 // opt_param_len = 10, but total size is 10
  };
  EXPECT_FALSE(
      bgp::BgpParser::parseOpen(optTooLarge.data(), optTooLarge.size(), open));

  // Valid OPEN message
  std::vector<uint8_t> validOpen = {
      4,                      // version 4
      0x00, 0x64,             // my_as = 100
      0x00, 0x3C,             // hold_time = 60
      192,  0,    2,    1,    // bgp_id = 192.0.2.1
      4,                      // opt_param_len = 4
      0x02, 0x02, 0x01, 0x00  // opt params
  };
  EXPECT_TRUE(
      bgp::BgpParser::parseOpen(validOpen.data(), validOpen.size(), open));
  EXPECT_EQ(open.version, 4);
  EXPECT_EQ(open.my_as, 100);
  EXPECT_EQ(open.hold_time, 60);
  EXPECT_EQ(open.bgp_id, 0xC0000201);
  ASSERT_EQ(open.optional_parameters.size(), 4);
}

TEST(BgpParserTest, ParseUpdate) {
  bgp::BgpUpdateMessage update;

  // Too small to read withdrawn routes length (< 2 bytes)
  std::vector<uint8_t> tooSmall = {0x00};
  EXPECT_FALSE(
      bgp::BgpParser::parseUpdate(tooSmall.data(), tooSmall.size(), update));

  // Withdrawn len exceeds payload
  std::vector<uint8_t> withdrawnTooLong = {0x00, 0x05, 0x01};
  EXPECT_FALSE(bgp::BgpParser::parseUpdate(withdrawnTooLong.data(),
                                           withdrawnTooLong.size(), update));

  // Malformed withdrawn prefix
  std::vector<uint8_t> malformedWithdrawn = {0x00, 0x02, 24, 10};
  EXPECT_FALSE(bgp::BgpParser::parseUpdate(malformedWithdrawn.data(),
                                           malformedWithdrawn.size(), update));

  // No space for attr len after withdrawn routes
  std::vector<uint8_t> noAttrLen = {0x00, 0x00, 0x00};
  EXPECT_FALSE(
      bgp::BgpParser::parseUpdate(noAttrLen.data(), noAttrLen.size(), update));

  // Attr len exceeds payload
  std::vector<uint8_t> attrLenTooLong = {0x00, 0x00, 0x00, 0x05, 0x01};
  EXPECT_FALSE(bgp::BgpParser::parseUpdate(attrLenTooLong.data(),
                                           attrLenTooLong.size(), update));

  // Malformed attribute
  std::vector<uint8_t> malformedAttr = {0x00, 0x00, 0x00, 0x01, 0x40};
  EXPECT_FALSE(bgp::BgpParser::parseUpdate(malformedAttr.data(),
                                           malformedAttr.size(), update));

  // Malformed NLRI
  std::vector<uint8_t> malformedNlri = {
      0x00, 0x00,  // withdrawn len = 0
      0x00, 0x00,  // attr len = 0
      24,   192    // NLRI length 24 but only 1 byte prefix
  };
  EXPECT_FALSE(bgp::BgpParser::parseUpdate(malformedNlri.data(),
                                           malformedNlri.size(), update));

  // Valid complete UPDATE message (withdrawn, attribute, NLRI)
  std::vector<uint8_t> validUpdate = {
      0x00, 0x02,              // withdrawn len = 2
      8,    10,                // 10.0.0.0/8
      0x00, 0x04,              // attr len = 4
      0x40, 0x01, 0x01, 0x00,  // ORIGIN = IGP
      24,   192,  168,  1      // NLRI: 192.168.1.0/24
  };
  EXPECT_TRUE(bgp::BgpParser::parseUpdate(validUpdate.data(),
                                          validUpdate.size(), update));
  ASSERT_EQ(update.withdrawn_routes.size(), 1);
  EXPECT_EQ(update.withdrawn_routes[0].length, 8);
  ASSERT_EQ(update.attributes.size(), 1);
  EXPECT_EQ(update.attributes[0].type, bgp::BgpAttributeType::ORIGIN);
  ASSERT_EQ(update.nlri.size(), 1);
  EXPECT_EQ(update.nlri[0].length, 24);
}

TEST(BgpParserTest, DecodeAsPath) {
  bgp::BgpAsPath as_path;

  // Empty value
  EXPECT_TRUE(bgp::BgpParser::decodeAsPath({}, false, as_path));
  EXPECT_TRUE(as_path.segments.empty());

  // Truncated segment header (< 2 bytes)
  std::vector<uint8_t> truncHdr = {0x02};
  EXPECT_FALSE(bgp::BgpParser::decodeAsPath(truncHdr, false, as_path));

  // Segment count exceeds buffer
  std::vector<uint8_t> countTooBig = {0x02, 0x03, 0x00, 0x01};
  EXPECT_FALSE(bgp::BgpParser::decodeAsPath(countTooBig, false, as_path));

  // 2-byte AS path (AS_SEQUENCE and AS_SET)
  std::vector<uint8_t> as2Data = {
      0x02, 0x02, 0x00, 0x64, 0x00, 0xC8,  // AS_SEQUENCE: 100 200
      0x01, 0x01, 0x01, 0x2C               // AS_SET: {300}
  };
  EXPECT_TRUE(bgp::BgpParser::decodeAsPath(as2Data, false, as_path));
  ASSERT_EQ(as_path.segments.size(), 2);
  EXPECT_EQ(as_path.segments[0].type, 2);
  ASSERT_EQ(as_path.segments[0].asns.size(), 2);
  EXPECT_EQ(as_path.segments[0].asns[0], 100);
  EXPECT_EQ(as_path.segments[0].asns[1], 200);
  EXPECT_EQ(as_path.segments[1].type, 1);
  ASSERT_EQ(as_path.segments[1].asns.size(), 1);
  EXPECT_EQ(as_path.segments[1].asns[0], 300);

  // 4-byte AS path
  bgp::BgpAsPath as4Path;
  std::vector<uint8_t> as4Data = {
      0x02, 0x02, 0x00, 0x01, 0x00, 0x00,  // 65536
      0x00, 0x02, 0x00, 0x01               // 131073
  };
  EXPECT_TRUE(bgp::BgpParser::decodeAsPath(as4Data, true, as4Path));
  ASSERT_EQ(as4Path.segments.size(), 1);
  ASSERT_EQ(as4Path.segments[0].asns.size(), 2);
  EXPECT_EQ(as4Path.segments[0].asns[0], 65536);
  EXPECT_EQ(as4Path.segments[0].asns[1], 131073);
}

TEST(BgpParserTest, DecodeMpReachNlri) {
  bgp::BgpMpReachNlri mp_reach;

  // Size < 4
  EXPECT_FALSE(bgp::BgpParser::decodeMpReachNlri({0x00, 0x01, 0x01}, mp_reach));

  // Next hop length exceeds buffer
  std::vector<uint8_t> nhTooLong = {0x00, 0x02, 0x01, 0x10, 0x01, 0x02};
  EXPECT_FALSE(bgp::BgpParser::decodeMpReachNlri(nhTooLong, mp_reach));

  // Malformed NLRI
  std::vector<uint8_t> malformedNlri = {
      0x00, 0x02,        // AFI = 2 (IPv6)
      0x01,              // SAFI = 1 (Unicast)
      0x04,              // NH len = 4
      1,    2,    3, 4,  // NH
      0x00,              // Reserved
      64,   0x20         // NLRI /64 with only 1 byte
  };
  EXPECT_FALSE(bgp::BgpParser::decodeMpReachNlri(malformedNlri, mp_reach));

  // Valid MP_REACH_NLRI
  std::vector<uint8_t> validMpReach = {
      0x00, 0x02,          // AFI = 2 (IPv6)
      0x01,                // SAFI = 1
      0x04,                // NH len = 4
      10,   0,    0,   1,  // NH
      0x00,                // Reserved
      16,   0x20, 0x01     // NLRI: 2001::/16 (2 bytes prefix)
  };
  EXPECT_TRUE(bgp::BgpParser::decodeMpReachNlri(validMpReach, mp_reach, false));
  EXPECT_EQ(mp_reach.afi, 2);
  EXPECT_EQ(mp_reach.safi, 1);
  ASSERT_EQ(mp_reach.next_hop.size(), 4);
  EXPECT_EQ(mp_reach.next_hop[0], 10);
  ASSERT_EQ(mp_reach.nlri.size(), 1);
  EXPECT_EQ(mp_reach.nlri[0].length, 16);
}

TEST(BgpParserTest, DecodeMpUnreachNlri) {
  bgp::BgpMpUnreachNlri mp_unreach;

  // Size < 3
  EXPECT_FALSE(bgp::BgpParser::decodeMpUnreachNlri({0x00, 0x02}, mp_unreach));

  // Malformed withdrawn routes
  std::vector<uint8_t> malformedWithdrawn = {
      0x00, 0x02,  // AFI = 2
      0x01,        // SAFI = 1
      64, 0x20     // /64 with 1 byte prefix
  };
  EXPECT_FALSE(
      bgp::BgpParser::decodeMpUnreachNlri(malformedWithdrawn, mp_unreach));

  // Valid MP_UNREACH_NLRI
  std::vector<uint8_t> validMpUnreach = {0x00, 0x02, 0x01, 16, 0x20, 0x01};
  EXPECT_TRUE(
      bgp::BgpParser::decodeMpUnreachNlri(validMpUnreach, mp_unreach, false));
  EXPECT_EQ(mp_unreach.afi, 2);
  EXPECT_EQ(mp_unreach.safi, 1);
  ASSERT_EQ(mp_unreach.withdrawn_routes.size(), 1);
  EXPECT_EQ(mp_unreach.withdrawn_routes[0].length, 16);
}

TEST(BgpParserTest, DecodeCommunities) {
  std::vector<std::string> comms;

  // Invalid length (not multiple of 4)
  EXPECT_FALSE(bgp::BgpParser::decodeCommunities({0x01, 0x02, 0x03}, comms));

  // Valid communities
  std::vector<uint8_t> validComms = {
      0xFD, 0xE8, 0x00, 0x64,  // 65000:100
      0xFD, 0xE9, 0x00, 0xC8   // 65001:200
  };
  EXPECT_TRUE(bgp::BgpParser::decodeCommunities(validComms, comms));
  ASSERT_EQ(comms.size(), 2);
  EXPECT_EQ(comms[0], "65000:100");
  EXPECT_EQ(comms[1], "65001:200");
}

TEST(BgpParserTest, StringConversions) {
  // originToString
  EXPECT_EQ(bgp::BgpParser::originToString(0), "IGP");
  EXPECT_EQ(bgp::BgpParser::originToString(1), "EGP");
  EXPECT_EQ(bgp::BgpParser::originToString(2), "INCOMPLETE");
  EXPECT_EQ(bgp::BgpParser::originToString(3), "UNKNOWN");

  // attributeTypeToName
  EXPECT_EQ(bgp::BgpParser::attributeTypeToName(1), "ORIGIN");
  EXPECT_EQ(bgp::BgpParser::attributeTypeToName(2), "AS_PATH");
  EXPECT_EQ(bgp::BgpParser::attributeTypeToName(3), "NEXT_HOP");
  EXPECT_EQ(bgp::BgpParser::attributeTypeToName(4), "MULTI_EXIT_DISC");
  EXPECT_EQ(bgp::BgpParser::attributeTypeToName(5), "LOCAL_PREF");
  EXPECT_EQ(bgp::BgpParser::attributeTypeToName(6), "ATOMIC_AGGREGATE");
  EXPECT_EQ(bgp::BgpParser::attributeTypeToName(7), "AGGREGATOR");
  EXPECT_EQ(bgp::BgpParser::attributeTypeToName(8), "COMMUNITIES");
  EXPECT_EQ(bgp::BgpParser::attributeTypeToName(9), "ORIGINATOR_ID");
  EXPECT_EQ(bgp::BgpParser::attributeTypeToName(10), "CLUSTER_LIST");
  EXPECT_EQ(bgp::BgpParser::attributeTypeToName(14), "MP_REACH_NLRI");
  EXPECT_EQ(bgp::BgpParser::attributeTypeToName(15), "MP_UNREACH_NLRI");
  EXPECT_EQ(bgp::BgpParser::attributeTypeToName(16), "EXTENDED_COMMUNITIES");
  EXPECT_EQ(bgp::BgpParser::attributeTypeToName(17), "AS4_PATH");
  EXPECT_EQ(bgp::BgpParser::attributeTypeToName(18), "AS4_AGGREGATOR");
  EXPECT_EQ(bgp::BgpParser::attributeTypeToName(32), "LARGE_COMMUNITIES");
  EXPECT_EQ(bgp::BgpParser::attributeTypeToName(99), "UNKNOWN(99)");

  // messageTypeToName
  EXPECT_EQ(bgp::BgpParser::messageTypeToName(1), "OPEN");
  EXPECT_EQ(bgp::BgpParser::messageTypeToName(2), "UPDATE");
  EXPECT_EQ(bgp::BgpParser::messageTypeToName(3), "NOTIFICATION");
  EXPECT_EQ(bgp::BgpParser::messageTypeToName(4), "KEEPALIVE");
  EXPECT_EQ(bgp::BgpParser::messageTypeToName(5), "ROUTE_REFRESH");
  EXPECT_EQ(bgp::BgpParser::messageTypeToName(99), "UNKNOWN(99)");

  // prefixToString IPv4
  bgp::BgpPrefix p4;
  p4.length = 24;
  p4.prefix = {192, 0, 2};
  EXPECT_EQ(bgp::BgpParser::prefixToString(p4, false), "192.0.2.0/24");

  // prefixToString IPv6
  bgp::BgpPrefix p6;
  p6.length = 32;
  p6.prefix = {0x20, 0x01, 0x0D, 0xB8};
  EXPECT_EQ(bgp::BgpParser::prefixToString(p6, true), "2001:db8::/32");
}
