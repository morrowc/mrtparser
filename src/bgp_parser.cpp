#include "bgp_parser.h"
#include <arpa/inet.h>
#include <cstring>
#include <vector>

namespace bgp {

bool BgpParser::parseMessage(const uint8_t *buffer, size_t size,
                             BgpHeader &header, std::vector<uint8_t> &payload) {
  if (size < 19)
    return false;

  std::memcpy(header.marker, buffer, 16);
  header.length = ntohs(*(uint16_t *)(buffer + 16));
  header.type = static_cast<BgpMessageType>(buffer[18]);

  if (header.length > size)
    return false;

  payload.assign(buffer + 19, buffer + header.length);
  return true;
}

bool BgpParser::parseAttributes(const uint8_t *buffer, size_t size,
                                std::vector<BgpAttribute> &attributes) {
  size_t offset = 0;
  while (offset < size) {
    if (offset + 2 > size)
      return false;

    BgpAttribute attr;
    uint8_t flags = buffer[offset++];
    attr.flags.optional = (flags & 0x80) != 0;
    attr.flags.transitive = (flags & 0x40) != 0;
    attr.flags.partial = (flags & 0x20) != 0;
    attr.flags.extended_length = (flags & 0x10) != 0;

    attr.type = static_cast<BgpAttributeType>(buffer[offset++]);

    uint16_t len = 0;
    if (attr.flags.extended_length) {
      if (offset + 2 > size)
        return false;
      len = ntohs(*(uint16_t *)(buffer + offset));
      offset += 2;
    } else {
      if (offset + 1 > size)
        return false;
      len = buffer[offset++];
    }

    if (offset + len > size)
      return false;
    attr.value.assign(buffer + offset, buffer + offset + len);
    offset += len;

    attributes.push_back(std::move(attr));
  }
  return true;
}

} // namespace bgp
