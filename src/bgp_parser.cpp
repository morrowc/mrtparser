#include "bgp_parser.h"
#include <arpa/inet.h>
#include <cstring>
#include <string>
#include <vector>

namespace bgp {

bool BgpParser::parseMessage(const uint8_t *buffer, size_t size,
                             BgpHeader &header, std::vector<uint8_t> &payload) {
  if (size < 19) return false;

  std::memcpy(header.marker, buffer, 16);
  header.length = ntohs(*(uint16_t *)(buffer + 16));
  header.type = static_cast<BgpMessageType>(buffer[18]);

  if (header.length > size) return false;

  payload.assign(buffer + 19, buffer + header.length);
  return true;
}

bool BgpParser::parseAttributes(const uint8_t *buffer, size_t size,
                                std::vector<BgpAttribute> &attributes) {
  size_t offset = 0;
  while (offset < size) {
    if (offset + 2 > size) return false;

    BgpAttribute attr;
    uint8_t flags = buffer[offset++];
    attr.flags.optional = (flags & 0x80) != 0;
    attr.flags.transitive = (flags & 0x40) != 0;
    attr.flags.partial = (flags & 0x20) != 0;
    attr.flags.extended_length = (flags & 0x10) != 0;

    attr.type = static_cast<BgpAttributeType>(buffer[offset++]);

    uint16_t len = 0;
    if (attr.flags.extended_length) {
      if (offset + 2 > size) return false;
      len = ntohs(*(uint16_t *)(buffer + offset));
      offset += 2;
    } else {
      if (offset + 1 > size) return false;
      len = buffer[offset++];
    }

    if (offset + len > size) return false;
    attr.value.assign(buffer + offset, buffer + offset + len);
    offset += len;

    attributes.push_back(std::move(attr));
  }
  return true;
}

bool BgpParser::parseUpdate(const uint8_t *payload, size_t size,
                            BgpUpdateMessage &update, bool has_add_path) {
  size_t offset = 0;

  // Withdrawn Routes
  if (offset + 2 > size) return false;
  uint16_t withdrawn_len = ntohs(*(uint16_t *)(payload + offset));
  offset += 2;
  if (offset + withdrawn_len > size) return false;
  if (!parsePrefixes(payload + offset, withdrawn_len, update.withdrawn_routes,
                     has_add_path))
    return false;
  offset += withdrawn_len;

  // Path Attributes
  if (offset + 2 > size) return false;
  uint16_t attr_len = ntohs(*(uint16_t *)(payload + offset));
  offset += 2;
  if (offset + attr_len > size) return false;
  if (!parseAttributes(payload + offset, attr_len, update.attributes))
    return false;
  offset += attr_len;

  // NLRI
  if (offset < size) {
    if (!parsePrefixes(payload + offset, size - offset, update.nlri,
                       has_add_path))
      return false;
  }

  return true;
}

bool BgpParser::parseOpen(const uint8_t *payload, size_t size,
                          BgpOpenMessage &open) {
  if (size < 10) return false;

  open.version = payload[0];
  open.my_as = ntohs(*(uint16_t *)(payload + 1));
  open.hold_time = ntohs(*(uint16_t *)(payload + 3));
  open.bgp_id = ntohl(*(uint32_t *)(payload + 5));

  uint8_t opt_param_len = payload[9];
  if (10 + opt_param_len > size) return false;

  open.optional_parameters.assign(payload + 10, payload + 10 + opt_param_len);
  return true;
}

bool BgpParser::parsePrefixes(const uint8_t *buffer, size_t size,
                              std::vector<BgpPrefix> &prefixes,
                              bool has_add_path) {
  size_t offset = 0;
  while (offset < size) {
    BgpPrefix prefix;
    prefix.has_path_id = has_add_path;
    if (has_add_path) {
      if (offset + 4 > size) return false;
      prefix.path_id = ntohl(*(uint32_t *)(buffer + offset));
      offset += 4;
    }

    if (offset + 1 > size) return false;
    prefix.length = buffer[offset++];
    uint8_t bytes = (prefix.length + 7) / 8;

    if (offset + bytes > size) return false;
    prefix.prefix.assign(buffer + offset, buffer + offset + bytes);
    offset += bytes;

    prefixes.push_back(std::move(prefix));
  }
  return true;
}

bool BgpParser::decodeAsPath(const std::vector<uint8_t> &value, bool is_as4,
                             BgpAsPath &as_path) {
  size_t offset = 0;
  while (offset < value.size()) {
    if (offset + 2 > value.size()) return false;
    BgpAsPathSegment segment;
    segment.type = value[offset++];
    uint8_t count = value[offset++];
    size_t asn_size = is_as4 ? 4 : 2;

    if (offset + (count * asn_size) > value.size()) return false;

    for (int i = 0; i < count; ++i) {
      uint32_t asn;
      if (is_as4) {
        asn = ntohl(*(uint32_t *)(value.data() + offset));
      } else {
        asn = ntohs(*(uint16_t *)(value.data() + offset));
      }
      segment.asns.push_back(asn);
      offset += asn_size;
    }
    as_path.segments.push_back(std::move(segment));
  }
  return true;
}

bool BgpParser::decodeMpReachNlri(const std::vector<uint8_t> &value,
                                  BgpMpReachNlri &mp_reach, bool has_add_path) {
  if (value.size() < 4) return false;
  size_t offset = 0;
  mp_reach.afi = ntohs(*(uint16_t *)(value.data() + offset));
  offset += 2;
  mp_reach.safi = value[offset++];
  uint8_t nh_len = value[offset++];
  if (offset + nh_len + 1 > value.size()) return false;
  mp_reach.next_hop.assign(value.data() + offset,
                           value.data() + offset + nh_len);
  offset += nh_len;
  offset++;  // Reserved byte

  return parsePrefixes(value.data() + offset, value.size() - offset,
                       mp_reach.nlri, has_add_path);
}

bool BgpParser::decodeMpUnreachNlri(const std::vector<uint8_t> &value,
                                    BgpMpUnreachNlri &mp_unreach,
                                    bool has_add_path) {
  if (value.size() < 3) return false;
  size_t offset = 0;
  mp_unreach.afi = ntohs(*(uint16_t *)(value.data() + offset));
  offset += 2;
  mp_unreach.safi = value[offset++];

  return parsePrefixes(value.data() + offset, value.size() - offset,
                       mp_unreach.withdrawn_routes, has_add_path);
}

std::string BgpParser::originToString(uint8_t origin) {
  switch (origin) {
    case 0:
      return "IGP";
    case 1:
      return "EGP";
    case 2:
      return "INCOMPLETE";
    default:
      return "UNKNOWN";
  }
}

std::string BgpParser::attributeTypeToName(uint8_t type) {
  switch (static_cast<BgpAttributeType>(type)) {
    case BgpAttributeType::ORIGIN:
      return "ORIGIN";
    case BgpAttributeType::AS_PATH:
      return "AS_PATH";
    case BgpAttributeType::NEXT_HOP:
      return "NEXT_HOP";
    case BgpAttributeType::MULTI_EXIT_DISC:
      return "MULTI_EXIT_DISC";
    case BgpAttributeType::LOCAL_PREF:
      return "LOCAL_PREF";
    case BgpAttributeType::ATOMIC_AGGREGATE:
      return "ATOMIC_AGGREGATE";
    case BgpAttributeType::AGGREGATOR:
      return "AGGREGATOR";
    case BgpAttributeType::COMMUNITIES:
      return "COMMUNITIES";
    case BgpAttributeType::ORIGINATOR_ID:
      return "ORIGINATOR_ID";
    case BgpAttributeType::CLUSTER_LIST:
      return "CLUSTER_LIST";
    case BgpAttributeType::MP_REACH_NLRI:
      return "MP_REACH_NLRI";
    case BgpAttributeType::MP_UNREACH_NLRI:
      return "MP_UNREACH_NLRI";
    case BgpAttributeType::EXTENDED_COMMUNITIES:
      return "EXTENDED_COMMUNITIES";
    case BgpAttributeType::AS4_PATH:
      return "AS4_PATH";
    case BgpAttributeType::AS4_AGGREGATOR:
      return "AS4_AGGREGATOR";
    case BgpAttributeType::LARGE_COMMUNITIES:
      return "LARGE_COMMUNITIES";
    default:
      return "UNKNOWN(" + std::to_string((int)type) + ")";
  }
}

std::string BgpParser::messageTypeToName(uint8_t type) {
  switch (static_cast<BgpMessageType>(type)) {
    case BgpMessageType::OPEN:
      return "OPEN";
    case BgpMessageType::UPDATE:
      return "UPDATE";
    case BgpMessageType::NOTIFICATION:
      return "NOTIFICATION";
    case BgpMessageType::KEEPALIVE:
      return "KEEPALIVE";
    case BgpMessageType::ROUTE_REFRESH:
      return "ROUTE_REFRESH";
    default:
      return "UNKNOWN(" + std::to_string((int)type) + ")";
  }
}

std::string BgpParser::prefixToString(const BgpPrefix &prefix, bool is_ipv6) {
  uint8_t addr[16] = {0};
  size_t addr_len = is_ipv6 ? 16 : 4;

  for (size_t i = 0; i < prefix.prefix.size() && i < addr_len; ++i) {
    addr[i] = prefix.prefix[i];
  }

  char buf[INET6_ADDRSTRLEN];
  if (inet_ntop(is_ipv6 ? AF_INET6 : AF_INET, addr, buf, sizeof(buf)) == NULL) {
    return "invalid";
  }

  return std::string(buf) + "/" + std::to_string((int)prefix.length);
}

}  // namespace bgp
