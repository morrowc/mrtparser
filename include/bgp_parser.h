#ifndef BGP_PARSER_H
#define BGP_PARSER_H

#include <cstdint>
#include <string>
#include <vector>

namespace bgp {

// BGP Message Types
enum class BgpMessageType : uint8_t {
  OPEN = 1,
  UPDATE = 2,
  NOTIFICATION = 3,
  KEEPALIVE = 4,
  ROUTE_REFRESH = 5
};

// BGP Attribute Type Codes (RFC 4271 & others)
enum class BgpAttributeType : uint8_t {
  ORIGIN = 1,
  AS_PATH = 2,
  NEXT_HOP = 3,
  MULTI_EXIT_DISC = 4,
  LOCAL_PREF = 5,
  ATOMIC_AGGREGATE = 6,
  AGGREGATOR = 7,
  COMMUNITIES = 8,
  ORIGINATOR_ID = 9,
  CLUSTER_LIST = 10,
  MP_REACH_NLRI = 14,
  MP_UNREACH_NLRI = 15,
  EXTENDED_COMMUNITIES = 16,
  AS4_PATH = 17,
  AS4_AGGREGATOR = 18,
  LARGE_COMMUNITIES = 32
};

// BGP Attribute Flags
struct BgpAttributeFlags {
  bool optional;
  bool transitive;
  bool partial;
  bool extended_length;
};

struct BgpAttribute {
  BgpAttributeFlags flags;
  BgpAttributeType type;
  std::vector<uint8_t> value;
};

struct BgpHeader {
  uint8_t marker[16];
  uint16_t length;
  BgpMessageType type;
};

class BgpParser {
 public:
  static bool parseMessage(const uint8_t *buffer, size_t size,
                           BgpHeader &header, std::vector<uint8_t> &payload);
  static bool parseAttributes(const uint8_t *buffer, size_t size,
                              std::vector<BgpAttribute> &attributes);
};

}  // namespace bgp

#endif  // BGP_PARSER_H
