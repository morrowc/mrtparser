#include "mrt_parser.h"
#include <arpa/inet.h>
#include <bzlib.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <zlib.h>
#include "bgp_parser.h"

namespace mrt {

class MrtParserImpl {
 public:
  virtual ~MrtParserImpl() = default;
  virtual size_t read(uint8_t *buffer, size_t size) = 0;
};

class RawMrtParserImpl : public MrtParserImpl {
 public:
  RawMrtParserImpl(const std::string &filename)
      : file(filename, std::ios::binary) {}
  size_t read(uint8_t *buffer, size_t size) override {
    file.read(reinterpret_cast<char *>(buffer), size);
    return file.gcount();
  }

 private:
  std::ifstream file;
};

class Bz2MrtParserImpl : public MrtParserImpl {
 public:
  Bz2MrtParserImpl(const std::string &filename) {
    file = std::fopen(filename.c_str(), "rb");
    int bzError;
    bzFile = BZ2_bzReadOpen(&bzError, file, 0, 0, NULL, 0);
  }
  ~Bz2MrtParserImpl() {
    int bzError;
    BZ2_bzReadClose(&bzError, bzFile);
    std::fclose(file);
  }
  size_t read(uint8_t *buffer, size_t size) override {
    int bzError;
    int nread = BZ2_bzRead(&bzError, bzFile, buffer, size);
    return (bzError == BZ_OK || bzError == BZ_STREAM_END) ? nread : 0;
  }

 private:
  FILE *file;
  BZFILE *bzFile;
};

MrtParser::MrtParser(const std::string &filename) {
  if (filename.size() > 4 && filename.substr(filename.size() - 4) == ".bz2") {
    impl = std::make_unique<Bz2MrtParserImpl>(filename);
  } else {
    impl = std::make_unique<RawMrtParserImpl>(filename);
  }
}

MrtParser::~MrtParser() = default;

bool MrtParser::nextRecord(MrtRecord &record) {
  uint8_t headerBuf[12];
  if (impl->read(headerBuf, 12) < 12) return false;

  record.header.timestamp = ntohl(*(uint32_t *)headerBuf);
  record.header.type = ntohs(*(uint16_t *)(headerBuf + 4));
  record.header.subtype = ntohs(*(uint16_t *)(headerBuf + 6));
  record.header.length = ntohl(*(uint32_t *)(headerBuf + 8));

  record.has_et = (record.header.type == (uint16_t)MrtType::BGP4MP_ET ||
                   record.header.type == (uint16_t)MrtType::ISIS_ET ||
                   record.header.type == (uint16_t)MrtType::OSPFv3_ET);

  uint32_t remainingLength = record.header.length;
  if (record.has_et) {
    uint8_t etBuf[4];
    if (impl->read(etBuf, 4) < 4) return false;
    record.microsecond_timestamp = ntohl(*(uint32_t *)etBuf);
    remainingLength -= 4;
  }

  record.message.resize(remainingLength);
  if (impl->read(record.message.data(), remainingLength) < remainingLength)
    return false;

  // Post-process based on type
  if (record.header.type == (uint16_t)MrtType::TABLE_DUMP_V2) {
    parseTableDumpV2(record);
  }

  return true;
}

void MrtParser::parseTableDumpV2(MrtRecord &record) {
  const uint8_t *data = record.message.data();
  size_t size = record.message.size();
  size_t offset = 0;

  TableDumpV2Subtype subtype =
      static_cast<TableDumpV2Subtype>(record.header.subtype);

  if (subtype == TableDumpV2Subtype::PEER_INDEX_TABLE) {
    record.peer_index_table = std::make_unique<PeerIndexTable>();
    if (size < 4) return;
    record.peer_index_table->collector_bgp_id = ntohl(*(uint32_t *)data);
    offset += 4;

    uint16_t view_name_len = ntohs(*(uint16_t *)(data + offset));
    offset += 2;
    if (offset + view_name_len > size) return;
    record.peer_index_table->view_name.assign((const char *)data + offset,
                                              view_name_len);
    offset += view_name_len;

    uint16_t peer_count = ntohs(*(uint16_t *)(data + offset));
    offset += 2;

    for (int i = 0; i < peer_count; ++i) {
      if (offset + 1 > size) break;
      PeerEntry peer;
      peer.peer_type = data[offset++];
      if (offset + 4 > size) break;
      peer.peer_bgp_id = ntohl(*(uint32_t *)(data + offset));
      offset += 4;

      bool is_ipv6 = (peer.peer_type & 0x01) != 0;
      bool is_as4 = (peer.peer_type & 0x02) != 0;

      if (is_ipv6) {
        if (offset + 16 > size) break;
        // Simple representation for now
        peer.peer_ip = "IPv6...";
        offset += 16;
      } else {
        if (offset + 4 > size) break;
        struct in_addr addr;
        addr.s_addr = *(uint32_t *)(data + offset);
        peer.peer_ip = inet_ntoa(addr);
        offset += 4;
      }

      if (is_as4) {
        if (offset + 4 > size) break;
        peer.peer_as = ntohl(*(uint32_t *)(data + offset));
        offset += 4;
      } else {
        if (offset + 2 > size) break;
        peer.peer_as = ntohs(*(uint16_t *)(data + offset));
        offset += 2;
      }
      record.peer_index_table->peers.push_back(std::move(peer));
    }
  } else if (subtype >= TableDumpV2Subtype::RIB_IPV4_UNICAST &&
             subtype <= TableDumpV2Subtype::RIB_GENERIC_ADDPATH) {
    record.rib_record = std::make_unique<RibRecord>();
    if (size < 4) return;
    record.rib_record->sequence_number = ntohl(*(uint32_t *)data);
    offset += 4;

    if (offset + 1 > size) return;
    record.rib_record->prefix_length = data[offset++];
    uint8_t prefix_bytes = (record.rib_record->prefix_length + 7) / 8;

    if (offset + prefix_bytes > size) return;
    record.rib_record->prefix.assign(data + offset,
                                     data + offset + prefix_bytes);
    offset += prefix_bytes;

    if (offset + 2 > size) return;
    uint16_t entry_count = ntohs(*(uint16_t *)(data + offset));
    offset += 2;

    for (int i = 0; i < entry_count; ++i) {
      if (offset + 4 > size) break;
      RibEntry entry;
      entry.peer_index = ntohs(*(uint16_t *)(data + offset));
      entry.originated_time = ntohl(*(uint32_t *)(data + offset + 2));
      offset += 6;

      uint16_t attr_len = ntohs(*(uint16_t *)(data + offset));
      offset += 2;

      if (offset + attr_len > size) break;
      bgp::BgpParser::parseAttributes(data + offset, attr_len,
                                      entry.attributes);
      offset += attr_len;

      record.rib_record->entries.push_back(std::move(entry));
    }
  }
}

std::string MrtParser::typeToString(uint16_t type) {
  switch (static_cast<MrtType>(type)) {
    case MrtType::OSPFv2:
      return "OSPFv2";
    case MrtType::TABLE_DUMP:
      return "TABLE_DUMP";
    case MrtType::TABLE_DUMP_V2:
      return "TABLE_DUMP_V2";
    case MrtType::BGP4MP:
      return "BGP4MP";
    case MrtType::BGP4MP_ET:
      return "BGP4MP_ET";
    case MrtType::ISIS:
      return "ISIS";
    case MrtType::ISIS_ET:
      return "ISIS_ET";
    case MrtType::OSPFv3:
      return "OSPFv3";
    case MrtType::OSPFv3_ET:
      return "OSPFv3_ET";
    default:
      return "UNKNOWN(" + std::to_string(type) + ")";
  }
}

std::string MrtParser::subtypeToString(uint16_t type, uint16_t subtype) {
  if (type == static_cast<uint16_t>(MrtType::TABLE_DUMP_V2)) {
    switch (static_cast<TableDumpV2Subtype>(subtype)) {
      case TableDumpV2Subtype::PEER_INDEX_TABLE:
        return "PEER_INDEX_TABLE";
      case TableDumpV2Subtype::RIB_IPV4_UNICAST:
        return "RIB_IPV4_UNICAST";
      case TableDumpV2Subtype::RIB_IPV4_MULTICAST:
        return "RIB_IPV4_MULTICAST";
      case TableDumpV2Subtype::RIB_IPV6_UNICAST:
        return "RIB_IPV6_UNICAST";
      case TableDumpV2Subtype::RIB_IPV6_MULTICAST:
        return "RIB_IPV6_MULTICAST";
      case TableDumpV2Subtype::RIB_GENERIC:
        return "RIB_GENERIC";
      case TableDumpV2Subtype::RIB_IPV4_UNICAST_ADDPATH:
        return "RIB_IPV4_UNICAST_ADDPATH";
      case TableDumpV2Subtype::RIB_IPV4_MULTICAST_ADDPATH:
        return "RIB_IPV4_MULTICAST_ADDPATH";
      case TableDumpV2Subtype::RIB_IPV6_UNICAST_ADDPATH:
        return "RIB_IPV6_UNICAST_ADDPATH";
      case TableDumpV2Subtype::RIB_IPV6_MULTICAST_ADDPATH:
        return "RIB_IPV6_MULTICAST_ADDPATH";
      case TableDumpV2Subtype::RIB_GENERIC_ADDPATH:
        return "RIB_GENERIC_ADDPATH";
      default:
        return std::to_string(subtype);
    }
  } else if (type == static_cast<uint16_t>(MrtType::BGP4MP) ||
             type == static_cast<uint16_t>(MrtType::BGP4MP_ET)) {
    switch (static_cast<Bgp4mpSubtype>(subtype)) {
      case Bgp4mpSubtype::BGP4MP_STATE_CHANGE:
        return "BGP4MP_STATE_CHANGE";
      case Bgp4mpSubtype::BGP4MP_MESSAGE:
        return "BGP4MP_MESSAGE";
      case Bgp4mpSubtype::BGP4MP_MESSAGE_AS4:
        return "BGP4MP_MESSAGE_AS4";
      case Bgp4mpSubtype::BGP4MP_STATE_CHANGE_AS4:
        return "BGP4MP_STATE_CHANGE_AS4";
      case Bgp4mpSubtype::BGP4MP_MESSAGE_LOCAL:
        return "BGP4MP_MESSAGE_LOCAL";
      case Bgp4mpSubtype::BGP4MP_MESSAGE_AS4_LOCAL:
        return "BGP4MP_MESSAGE_AS4_LOCAL";
      case Bgp4mpSubtype::BGP4MP_MESSAGE_ADDPATH:
        return "BGP4MP_MESSAGE_ADDPATH";
      case Bgp4mpSubtype::BGP4MP_MESSAGE_AS4_ADDPATH:
        return "BGP4MP_MESSAGE_AS4_ADDPATH";
      case Bgp4mpSubtype::BGP4MP_MESSAGE_LOCAL_ADDPATH:
        return "BGP4MP_MESSAGE_LOCAL_ADDPATH";
      case Bgp4mpSubtype::BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH:
        return "BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH";
      default:
        return std::to_string(subtype);
    }
  }
  return std::to_string(subtype);
}

}  // namespace mrt
