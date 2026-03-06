#include "bgp_parser.h"
#include "mrt_parser.h"
#include <iomanip>
#include <iostream>
#include <vector>

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << " <mrt_file>" << std::endl;
    return 1;
  }

  std::string filename = argv[1];
  mrt::MrtParser parser(filename);
  mrt::MrtRecord record;

  int recordCount = 0;
  while (parser.nextRecord(record)) {
    recordCount++;
    std::cout << "Record " << recordCount << ":" << std::endl;
    std::cout << "  Timestamp: " << record.header.timestamp << std::endl;
    std::cout << "  Type:      " << (int)record.header.type << std::endl;
    std::cout << "  Subtype:   " << (int)record.header.subtype << std::endl;
    std::cout << "  Length:    " << record.header.length << std::endl;
    if (record.has_et) {
      std::cout << "  Microsec:  " << record.microsecond_timestamp << std::endl;
    }

    // Basic BGP message parsing if it's BGP4MP
    if (record.header.type == (uint16_t)mrt::MrtType::BGP4MP ||
        record.header.type == (uint16_t)mrt::MrtType::BGP4MP_ET) {

      size_t bgp_offset = 0;
      // BGP4MP Common Header: Peer AS (2 or 4), Local AS (2 or 4), Interface
      // Index (2), Address Family (2) Plus Peer IP and Local IP (variable)
      bool is_as4 =
          (record.header.subtype ==
               (uint16_t)mrt::Bgp4mpSubtype::BGP4MP_MESSAGE_AS4 ||
           record.header.subtype ==
               (uint16_t)mrt::Bgp4mpSubtype::BGP4MP_MESSAGE_AS4_LOCAL ||
           record.header.subtype ==
               (uint16_t)mrt::Bgp4mpSubtype::BGP4MP_MESSAGE_AS4_ADDPATH ||
           record.header.subtype ==
               (uint16_t)mrt::Bgp4mpSubtype::BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH);

      bgp_offset += (is_as4 ? 8 : 4); // Peer AS + Local AS
      bgp_offset += 2;                // Interface Index
      uint16_t afi = ntohs(*(uint16_t *)(record.message.data() + bgp_offset));
      bgp_offset += 2;

      size_t ip_len = (afi == 1 ? 4 : 16);
      bgp_offset += (ip_len * 2); // Peer IP + Local IP

      if (bgp_offset < record.message.size()) {
        bgp::BgpHeader bgpHeader;
        std::vector<uint8_t> bgpPayload;
        if (bgp::BgpParser::parseMessage(record.message.data() + bgp_offset,
                                         record.message.size() - bgp_offset,
                                         bgpHeader, bgpPayload)) {
          std::cout << "    BGP Type: " << (int)bgpHeader.type
                    << " (Length: " << bgpHeader.length << ")" << std::endl;
          if (bgpHeader.type == bgp::BgpMessageType::UPDATE) {
            // Further update parsing...
          }
        }
      }
    }

    if (record.rib_record) {
      std::cout << "    RIB Prefix: " << (int)record.rib_record->prefix_length
                << " bits" << std::endl;
      std::cout << "    RIB Entries: " << record.rib_record->entries.size()
                << std::endl;
      for (const auto &entry : record.rib_record->entries) {
        std::cout << "      Peer Index: " << entry.peer_index << std::endl;
        std::cout << "      Attributes: " << entry.attributes.size()
                  << std::endl;
        for (const auto &attr : entry.attributes) {
          std::cout << "        Attr Type: " << (int)attr.type
                    << " (Len: " << attr.value.size() << ")" << std::endl;
        }
      }
    }

    std::cout << std::endl;
    if (recordCount >= 5)
      break; // Limit for now
  }

  return 0;
}
