#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <vector>
#include "bgp_parser.h"
#include "mrt_parser.h"

using json = nlohmann::json;

namespace bgp {
// Serialization for BGP types
NLOHMANN_JSON_SERIALIZE_ENUM(BgpMessageType,
                             {{BgpMessageType::OPEN, "Open"},
                              {BgpMessageType::UPDATE, "Update"},
                              {BgpMessageType::NOTIFICATION, "Notification"},
                              {BgpMessageType::KEEPALIVE, "Keepalive"},
                              {BgpMessageType::ROUTE_REFRESH, "RouteRefresh"}})

NLOHMANN_JSON_SERIALIZE_ENUM(BgpAttributeType,
                             {{BgpAttributeType::ORIGIN, "Origin"},
                              {BgpAttributeType::AS_PATH, "AsPath"},
                              {BgpAttributeType::NEXT_HOP, "NextHop"},
                              {BgpAttributeType::MULTI_EXIT_DISC, "MultiExitDisc"},
                              {BgpAttributeType::LOCAL_PREF, "LocalPref"},
                              {BgpAttributeType::ATOMIC_AGGREGATE, "AtomicAggregate"},
                              {BgpAttributeType::AGGREGATOR, "Aggregator"},
                              {BgpAttributeType::COMMUNITIES, "Communities"},
                              {BgpAttributeType::ORIGINATOR_ID, "OriginatorId"},
                              {BgpAttributeType::CLUSTER_LIST, "ClusterList"},
                              {BgpAttributeType::MP_REACH_NLRI, "MpReachNlri"},
                              {BgpAttributeType::MP_UNREACH_NLRI, "MpUnreachNlri"},
                              {BgpAttributeType::EXTENDED_COMMUNITIES, "ExtendedCommunities"},
                              {BgpAttributeType::AS4_PATH, "As4Path"},
                              {BgpAttributeType::AS4_AGGREGATOR, "As4Aggregator"},
                              {BgpAttributeType::LARGE_COMMUNITIES, "LargeCommunities"}})

void to_json(json &j, const BgpAttributeFlags &f) {
  j = json{{"optional", f.optional},
           {"transitive", f.transitive},
           {"partial", f.partial},
           {"extended_length", f.extended_length}};
}
void to_json(json &j, const BgpAttribute &a) {
  j = json{{"flags", a.flags}, {"attr_type", a.type}, {"value", a.value}};
}
void to_json(json &j, const BgpPrefix &p) {
  j = json{{"path_id", p.has_path_id ? json(p.path_id) : json(nullptr)},
           {"length", p.length},
           {"prefix", p.prefix}};
}
void to_json(json &j, const BgpUpdateMessage &m) {
  j = json{{"withdrawn_routes", m.withdrawn_routes},
           {"attributes", m.attributes},
           {"nlri", m.nlri}};
}
}  // namespace bgp

namespace mrt {
// Serialization for MRT types
NLOHMANN_JSON_SERIALIZE_ENUM(MrtType,
                             {{MrtType::OSPFv2, "Ospfv2"},
                              {MrtType::TABLE_DUMP, "TableDump"},
                              {MrtType::TABLE_DUMP_V2, "TableDumpV2"},
                              {MrtType::BGP4MP, "Bgp4mp"},
                              {MrtType::BGP4MP_ET, "Bgp4mpEt"},
                              {MrtType::ISIS, "Isis"},
                              {MrtType::ISIS_ET, "IsisEt"},
                              {MrtType::OSPFv3, "Ospfv3"},
                              {MrtType::OSPFv3_ET, "Ospfv3Et"}})

void to_json(json &j, const MrtHeader &h) {
  j = json{{"timestamp", h.timestamp},
           {"mrt_type", static_cast<MrtType>(h.type)},
           {"subtype", h.subtype},
           {"length", h.length}};
}
void to_json(json &j, const PeerEntry &e) {
  j = json{{"peer_type", e.peer_type},
           {"peer_bgp_id", e.peer_bgp_id},
           {"peer_ip", e.peer_ip},
           {"peer_as", e.peer_as}};
}
void to_json(json &j, const PeerIndexTable &t) {
  j = json{{"collector_bgp_id", t.collector_bgp_id},
           {"view_name", t.view_name},
           {"peers", t.peers}};
}
void to_json(json &j, const RibEntry &e) {
  j = json{{"peer_index", e.peer_index},
           {"originated_time", e.originated_time},
           {"attributes", e.attributes}};
}
void to_json(json &j, const RibRecord &r) {
  j = json{{"sequence_number", r.sequence_number},
           {"prefix_length", r.prefix_length},
           {"prefix", r.prefix},
           {"entries", r.entries}};
}
void to_json(json &j, const MrtRecord &r) {
  j = json{{"header", r.header},
           {"microsecond_timestamp",
            r.has_et ? json(r.microsecond_timestamp) : json(nullptr)},
           {"data", r.message},
           {"peer_index_table", r.peer_index_table ? json(*r.peer_index_table)
                                                   : json(nullptr)},
           {"rib_record",
            r.rib_record ? json(*r.rib_record) : json(nullptr)}};
}
}  // namespace mrt

std::string timestampToUtc(uint32_t timestamp) {
  time_t t = static_cast<time_t>(timestamp);
  struct tm *tm_info = gmtime(&t);
  char buf[20];
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);
  return std::string(buf);
}

int main(int argc, char *argv[]) {
  bool utc = false;
  bool singleLine = false;
  bool jsonOutput = false;
  std::vector<std::string> filenames;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--utc") {
      utc = true;
    } else if (arg == "--single-line") {
      singleLine = true;
    } else if (arg == "--json") {
      jsonOutput = true;
    } else {
      filenames.push_back(arg);
    }
  }

  if (filenames.empty()) {
    std::cerr << "Usage: " << argv[0]
              << " [--utc] [--single-line] [--json] <mrt_file> [mrt_file ...]"
              << std::endl;
    return 1;
  }

  for (const auto &filename : filenames) {
    if (filenames.size() > 1 && !jsonOutput) {
      std::cout << "Processing file: " << filename << std::endl;
    }

    mrt::MrtParser parser(filename);
    mrt::MrtRecord record;

    int recordCount = 0;
    while (parser.nextRecord(record)) {
      recordCount++;

      if (jsonOutput) {
        std::cout << json(record).dump() << std::endl;
        continue;
      }

      std::stringstream ss;
      if (singleLine) {
        ss << "Record " << recordCount << ": ";
        ss << "Timestamp: "
           << (utc ? timestampToUtc(record.header.timestamp)
                   : std::to_string(record.header.timestamp))
           << " ";
        ss << "Type: " << mrt::MrtParser::typeToString(record.header.type)
           << " ";
        ss << "Subtype: "
           << mrt::MrtParser::subtypeToString(record.header.type,
                                              record.header.subtype)
           << " ";
        ss << "Length: " << record.header.length << " ";
        if (record.has_et)
          ss << "Microsec: " << record.microsecond_timestamp << " ";
      } else {
        ss << "Record " << recordCount << ":" << std::endl;
        ss << "  Timestamp: "
           << (utc ? timestampToUtc(record.header.timestamp)
                   : std::to_string(record.header.timestamp))
           << std::endl;
        ss << "  Type:      "
           << mrt::MrtParser::typeToString(record.header.type) << std::endl;
        ss << "  Subtype:   "
           << mrt::MrtParser::subtypeToString(record.header.type,
                                              record.header.subtype)
           << std::endl;
        ss << "  Length:    " << record.header.length << std::endl;
        if (record.has_et)
          ss << "  Microsec:  " << record.microsecond_timestamp << std::endl;
      }

      // BGP4MP Parsing
      if (record.header.type == (uint16_t)mrt::MrtType::BGP4MP ||
          record.header.type == (uint16_t)mrt::MrtType::BGP4MP_ET) {
        size_t bgp_offset = 0;
        bool is_as4 =
            (record.header.subtype ==
                 (uint16_t)mrt::Bgp4mpSubtype::BGP4MP_MESSAGE_AS4 ||
             record.header.subtype ==
                 (uint16_t)mrt::Bgp4mpSubtype::BGP4MP_MESSAGE_AS4_LOCAL ||
             record.header.subtype ==
                 (uint16_t)mrt::Bgp4mpSubtype::BGP4MP_MESSAGE_AS4_ADDPATH ||
             record.header.subtype ==
                 (uint16_t)
                     mrt::Bgp4mpSubtype::BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH);

        bgp_offset += (is_as4 ? 8 : 4);
        bgp_offset += 2;
        uint16_t afi = ntohs(*(uint16_t *)(record.message.data() + bgp_offset));
        bgp_offset += 2;
        size_t ip_len = (afi == 1 ? 4 : 16);
        bgp_offset += (ip_len * 2);

        if (bgp_offset < record.message.size()) {
          bgp::BgpHeader bgpHeader;
          std::vector<uint8_t> bgpPayload;
          if (bgp::BgpParser::parseMessage(record.message.data() + bgp_offset,
                                           record.message.size() - bgp_offset,
                                           bgpHeader, bgpPayload)) {
            if (singleLine) {
              ss << "BGPType: "
                 << bgp::BgpParser::messageTypeToName((uint8_t)bgpHeader.type)
                 << " ";
            } else {
              ss << "    BGP Type: "
                 << bgp::BgpParser::messageTypeToName((uint8_t)bgpHeader.type)
                 << " (Length: " << bgpHeader.length << ")" << std::endl;
            }

            if (bgpHeader.type == bgp::BgpMessageType::UPDATE) {
              bgp::BgpUpdateMessage update;
              bool has_add_path =
                  (record.header.subtype ==
                       (uint16_t)
                           mrt::Bgp4mpSubtype::BGP4MP_MESSAGE_AS4_ADDPATH ||
                   record.header.subtype ==
                       (uint16_t)mrt::Bgp4mpSubtype::
                           BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH);
              if (bgp::BgpParser::parseUpdate(bgpPayload.data(),
                                              bgpPayload.size(), update,
                                              has_add_path)) {
                if (singleLine) {
                  if (!update.withdrawn_routes.empty()) {
                    ss << "Withdrawn:";
                    for (const auto &p : update.withdrawn_routes)
                      ss << " " << bgp::BgpParser::prefixToString(p, afi == 2);
                    ss << " ";
                  }
                  if (!update.nlri.empty()) {
                    ss << "NLRI:";
                    for (const auto &p : update.nlri)
                      ss << " " << bgp::BgpParser::prefixToString(p, afi == 2);
                    ss << " ";
                  }
                } else {
                  if (!update.withdrawn_routes.empty()) {
                    ss << "      Withdrawn (" << update.withdrawn_routes.size()
                       << "):";
                    for (const auto &p : update.withdrawn_routes)
                      ss << " " << bgp::BgpParser::prefixToString(p, afi == 2);
                    ss << std::endl;
                  }
                  if (!update.nlri.empty()) {
                    ss << "      NLRI (" << update.nlri.size() << "):";
                    for (const auto &p : update.nlri)
                      ss << " " << bgp::BgpParser::prefixToString(p, afi == 2);
                    ss << std::endl;
                  }
                }

                for (const auto &attr : update.attributes) {
                  if (singleLine) {
                    ss << bgp::BgpParser::attributeTypeToName(
                        (uint8_t)attr.type);
                  } else {
                    ss << "        Attribute: "
                       << bgp::BgpParser::attributeTypeToName(
                              (uint8_t)attr.type)
                       << " (Len: " << attr.value.size() << ")";
                  }

                  if (attr.type == bgp::BgpAttributeType::ORIGIN &&
                      attr.value.size() == 1) {
                    ss << (singleLine ? "=" : " ORIGIN=")
                       << bgp::BgpParser::originToString(attr.value[0]);
                  } else if (attr.type == bgp::BgpAttributeType::AS_PATH ||
                             attr.type == bgp::BgpAttributeType::AS4_PATH) {
                    bgp::BgpAsPath as_path;
                    bool as4_session =
                        (attr.type == bgp::BgpAttributeType::AS4_PATH) ||
                        is_as4;
                    if (bgp::BgpParser::decodeAsPath(attr.value, as4_session,
                                                     as_path)) {
                      ss << (singleLine ? "=" : " AS_PATH=");
                      for (const auto &seg : as_path.segments) {
                        ss << (seg.type == 1 ? "{" : "(");
                        for (size_t i = 0; i < seg.asns.size(); ++i)
                          ss << seg.asns[i]
                             << (i == seg.asns.size() - 1 ? "" : " ");
                        ss << (seg.type == 1 ? "}" : ")");
                      }
                    }
                  } else if (attr.type == bgp::BgpAttributeType::NEXT_HOP &&
                             attr.value.size() == 4) {
                    struct in_addr addr1;
                    std::memcpy(&addr1.s_addr, attr.value.data(), 4);
                    ss << (singleLine ? "=" : " NEXT_HOP=") << inet_ntoa(addr1);
                  } else if (attr.type ==
                             bgp::BgpAttributeType::MP_REACH_NLRI) {
                    bgp::BgpMpReachNlri mp_reach;
                    if (bgp::BgpParser::decodeMpReachNlri(attr.value, mp_reach,
                                                          has_add_path)) {
                      ss << (singleLine ? "=" : " MP_REACH AFI=")
                         << mp_reach.afi << " SAFI=" << (int)mp_reach.safi
                         << " NLRI:";
                      for (const auto &p : mp_reach.nlri)
                        ss << " "
                           << bgp::BgpParser::prefixToString(p,
                                                             mp_reach.afi == 2);
                    }
                  } else if (attr.type ==
                             bgp::BgpAttributeType::MP_UNREACH_NLRI) {
                    bgp::BgpMpUnreachNlri mp_unreach;
                    if (bgp::BgpParser::decodeMpUnreachNlri(
                            attr.value, mp_unreach, has_add_path)) {
                      ss << (singleLine ? "=" : " MP_UNREACH AFI=")
                         << mp_unreach.afi << " SAFI=" << (int)mp_unreach.safi
                         << " Withdrawn:";
                      for (const auto &p : mp_unreach.withdrawn_routes)
                        ss << " "
                           << bgp::BgpParser::prefixToString(
                                  p, mp_unreach.afi == 2);
                    }
                  } else if (attr.type == bgp::BgpAttributeType::COMMUNITIES) {
                    std::vector<std::string> communities;
                    if (bgp::BgpParser::decodeCommunities(attr.value,
                                                          communities)) {
                      ss << (singleLine ? "=" : " COMMUNITIES=");
                      for (size_t i = 0; i < communities.size(); ++i) {
                        ss << communities[i]
                           << (i == communities.size() - 1 ? "" : " ");
                      }
                    } else if (singleLine) {
                      ss << "[len=" << attr.value.size() << "]";
                    }
                  } else if (singleLine) {
                    ss << "[len=" << attr.value.size() << "]";
                  }
                  if (singleLine)
                    ss << " ";
                  else
                    ss << std::endl;
                }
              }
            } else if (bgpHeader.type == bgp::BgpMessageType::OPEN) {
              bgp::BgpOpenMessage open;
              if (bgp::BgpParser::parseOpen(bgpPayload.data(),
                                            bgpPayload.size(), open)) {
                if (singleLine) {
                  ss << "Version: " << (int)open.version
                     << " AS: " << open.my_as << " ID: " << open.bgp_id << " ";
                } else {
                  ss << "      Version: " << (int)open.version << std::endl;
                  ss << "      AS:      " << open.my_as << std::endl;
                  ss << "      HoldTime:" << open.hold_time << std::endl;
                  struct in_addr id_addr;
                  id_addr.s_addr = htonl(open.bgp_id);
                  ss << "      BGP ID:  " << inet_ntoa(id_addr) << std::endl;
                }
              }
            }
          }
        }
      }

      if (record.rib_record) {
        bgp::BgpPrefix rib_prefix;
        rib_prefix.length = record.rib_record->prefix_length;
        rib_prefix.prefix = record.rib_record->prefix;
        bool is_v6 =
            (record.header.subtype ==
                 (uint16_t)mrt::TableDumpV2Subtype::RIB_IPV6_UNICAST ||
             record.header.subtype ==
                 (uint16_t)mrt::TableDumpV2Subtype::RIB_IPV6_MULTICAST ||
             record.header.subtype ==
                 (uint16_t)mrt::TableDumpV2Subtype::RIB_IPV6_UNICAST_ADDPATH ||
             record.header.subtype ==
                 (uint16_t)mrt::TableDumpV2Subtype::RIB_IPV6_MULTICAST_ADDPATH);
        if (singleLine) {
          ss << "RIB: " << bgp::BgpParser::prefixToString(rib_prefix, is_v6)
             << " Entries: " << record.rib_record->entries.size() << " ";
        } else {
          ss << "    RIB Prefix: "
             << bgp::BgpParser::prefixToString(rib_prefix, is_v6) << std::endl;
          ss << "    RIB Entries: " << record.rib_record->entries.size()
             << std::endl;
        }
        for (const auto &entry : record.rib_record->entries) {
          if (!singleLine) {
            ss << "      Peer Index: " << entry.peer_index << std::endl;
            ss << "      Attributes: " << entry.attributes.size() << std::endl;
          }
          for (const auto &attr : entry.attributes) {
            if (singleLine) {
              ss << "EntryAttr: "
                 << bgp::BgpParser::attributeTypeToName((uint8_t)attr.type)
                 << " ";
            } else {
              ss << "        Attr Type: "
                 << bgp::BgpParser::attributeTypeToName((uint8_t)attr.type)
                 << " (Len: " << attr.value.size() << ")" << std::endl;
            }
          }
        }
      }

      std::cout << ss.str() << std::endl;
      if (recordCount >= 5 && !singleLine)
        break;  // Keep some limit for multi-line to avoid flood
    }
  }

  return 0;
}
