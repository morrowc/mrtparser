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

struct BgpPrefix {
  uint32_t path_id;  // RFC 8050 Add-Path
  uint8_t length;
  std::vector<uint8_t> prefix;
  bool has_path_id;

  BgpPrefix() : path_id(0), length(0), has_path_id(false) {}
};

struct BgpOpenMessage {
  uint8_t version;
  uint32_t my_as;
  uint16_t hold_time;
  uint32_t bgp_id;
  std::vector<uint8_t> optional_parameters;
};

struct BgpUpdateMessage {
  std::vector<BgpPrefix> withdrawn_routes;
  std::vector<BgpAttribute> attributes;
  std::vector<BgpPrefix> nlri;
};

class BgpParser {
 public:
  static bool parseMessage(const uint8_t *buffer, size_t size,
                           BgpHeader &header, std::vector<uint8_t> &payload);
  static bool parseAttributes(const uint8_t *buffer, size_t size,
                              std::vector<BgpAttribute> &attributes);
  static bool parseUpdate(const uint8_t *payload, size_t size,
                          BgpUpdateMessage &update, bool has_add_path = false);
  static bool parsePrefixes(const uint8_t *buffer, size_t size,
                            std::vector<BgpPrefix> &prefixes,
                            bool has_add_path = false);
};

}  // namespace bgp

#endif  // BGP_PARSER_H
