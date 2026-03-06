#ifndef MRT_PARSER_H
#define MRT_PARSER_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include "bgp_parser.h"

namespace mrt {

// RFC 6396 Section 2: MRT Common Header
struct MrtHeader {
  uint32_t timestamp;
  uint16_t type;
  uint16_t subtype;
  uint32_t length;
};

// RFC 6396 Section 3: Extended Timestamp
struct MrtHeaderET : public MrtHeader {
  uint32_t microsecond_timestamp;
};

// MRT Types (RFC 6396 Section 4)
enum class MrtType : uint16_t {
  OSPFv2 = 11,
  TABLE_DUMP = 12,
  TABLE_DUMP_V2 = 13,
  BGP4MP = 16,
  BGP4MP_ET = 17,
  ISIS = 32,
  ISIS_ET = 33,
  OSPFv3 = 48,
  OSPFv3_ET = 49
};

// TABLE_DUMP_V2 Subtypes (RFC 6396 Section 4.3)
enum class TableDumpV2Subtype : uint16_t {
  PEER_INDEX_TABLE = 1,
  RIB_IPV4_UNICAST = 2,
  RIB_IPV4_MULTICAST = 3,
  RIB_IPV6_UNICAST = 4,
  RIB_IPV6_MULTICAST = 5,
  RIB_GENERIC = 6,
  // Add-Path extensions (RFC 8050)
  RIB_IPV4_UNICAST_ADDPATH = 8,
  RIB_IPV4_MULTICAST_ADDPATH = 9,
  RIB_IPV6_UNICAST_ADDPATH = 10,
  RIB_IPV6_MULTICAST_ADDPATH = 11,
  RIB_GENERIC_ADDPATH = 12
};

// BGP4MP Subtypes (RFC 6396 Section 4.4)
enum class Bgp4mpSubtype : uint16_t {
  BGP4MP_STATE_CHANGE = 0,
  BGP4MP_MESSAGE = 1,
  BGP4MP_MESSAGE_AS4 = 4,
  BGP4MP_STATE_CHANGE_AS4 = 5,
  BGP4MP_MESSAGE_LOCAL = 6,
  BGP4MP_MESSAGE_AS4_LOCAL = 7,
  // Add-Path extensions (RFC 8050)
  BGP4MP_MESSAGE_ADDPATH = 8,
  BGP4MP_MESSAGE_AS4_ADDPATH = 9,
  BGP4MP_MESSAGE_LOCAL_ADDPATH = 10,
  BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH = 11
};

struct PeerEntry {
  uint8_t peer_type;
  uint32_t peer_bgp_id;
  std::string peer_ip;
  uint32_t peer_as;  // Supports 2-byte and 4-byte
};

struct PeerIndexTable {
  uint32_t collector_bgp_id;
  std::string view_name;
  std::vector<PeerEntry> peers;
};

struct RibEntry {
  uint16_t peer_index;
  uint32_t originated_time;
  // BGP Attributes are parsed separately
  std::vector<bgp::BgpAttribute> attributes;
};

struct RibRecord {
  uint32_t sequence_number;
  uint8_t prefix_length;
  std::vector<uint8_t> prefix;
  std::vector<RibEntry> entries;
};

class MrtRecord {
 public:
  MrtHeader header;
  uint32_t microsecond_timestamp;
  bool has_et;
  std::vector<uint8_t> message;

  // Specialized data
  std::unique_ptr<PeerIndexTable> peer_index_table;
  std::unique_ptr<RibRecord> rib_record;
  std::unique_ptr<bgp::BgpUpdateMessage> bgp_update;

  MrtRecord() : microsecond_timestamp(0), has_et(false) {}
};

class MrtParserImpl;

class MrtParser {
 public:
  MrtParser(const std::string &filename);
  ~MrtParser();

  bool nextRecord(MrtRecord &record);

 private:
  void parseTableDumpV2(MrtRecord &record);
  std::unique_ptr<MrtParserImpl> impl;
};

}  // namespace mrt

#endif  // MRT_PARSER_H
