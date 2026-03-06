#include "bgp_parser.h"
#include <arpa/inet.h>
#include <cstring>
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

}  // namespace bgp
