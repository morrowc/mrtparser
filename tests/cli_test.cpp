#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#ifndef MRTPARSER_BIN
#define MRTPARSER_BIN "./mrtparser"
#endif

#ifndef TESTDATA_DIR
#define TESTDATA_DIR "testdata"
#endif

namespace {

struct ExecResult {
  int exit_code;
  std::string stdout_str;
  std::string stderr_str;
};

ExecResult runCommand(const std::string &cmd) {
  ExecResult result;
  std::string full_cmd = cmd + " 2>&1";
  FILE *pipe = popen(full_cmd.c_str(), "r");
  if (!pipe) {
    result.exit_code = -1;
    return result;
  }
  char buffer[256];
  while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
    result.stdout_str += buffer;
  }
  int status = pclose(pipe);
  result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  return result;
}

std::string createSyntheticMrtFile(const std::string &filepath) {
  std::ofstream out(filepath, std::ios::binary);

  auto writeMrtRecord = [&](uint32_t ts, uint16_t type, uint16_t subtype,
                            const std::vector<uint8_t> &body,
                            bool has_et = false, uint32_t micro = 0) {
    uint32_t ts_net = htonl(ts);
    uint16_t type_net = htons(type);
    uint16_t subtype_net = htons(subtype);
    uint32_t len_net = htonl(body.size() + (has_et ? 4 : 0));

    out.write(reinterpret_cast<char *>(&ts_net), 4);
    out.write(reinterpret_cast<char *>(&type_net), 2);
    out.write(reinterpret_cast<char *>(&subtype_net), 2);
    out.write(reinterpret_cast<char *>(&len_net), 4);

    if (has_et) {
      uint32_t micro_net = htonl(micro);
      out.write(reinterpret_cast<char *>(&micro_net), 4);
    }
    out.write(reinterpret_cast<const char *>(body.data()), body.size());
  };

  // 1. TableDumpV2 PEER_INDEX_TABLE
  {
    std::vector<uint8_t> pit;
    uint32_t coll_id = htonl(0x01020304);
    const uint8_t *p = reinterpret_cast<const uint8_t *>(&coll_id);
    pit.insert(pit.end(), p, p + 4);
    uint16_t vlen = htons(4);
    p = reinterpret_cast<const uint8_t *>(&vlen);
    pit.insert(pit.end(), p, p + 2);
    pit.push_back('v');
    pit.push_back('i');
    pit.push_back('e');
    pit.push_back('w');
    uint16_t count = htons(2);
    p = reinterpret_cast<const uint8_t *>(&count);
    pit.insert(pit.end(), p, p + 2);

    // Peer 1: IPv4, 2-byte AS
    pit.push_back(0);  // peer_type
    uint32_t p1_id = htonl(0x0A000001);
    p = reinterpret_cast<const uint8_t *>(&p1_id);
    pit.insert(pit.end(), p, p + 4);
    uint8_t p1_ip[4] = {10, 0, 0, 1};
    pit.insert(pit.end(), p1_ip, p1_ip + 4);
    uint16_t p1_as = htons(65001);
    p = reinterpret_cast<const uint8_t *>(&p1_as);
    pit.insert(pit.end(), p, p + 2);

    // Peer 2: IPv6, 4-byte AS
    pit.push_back(3);  // peer_type (IPv6 | AS4)
    uint32_t p2_id = htonl(0x0A000002);
    p = reinterpret_cast<const uint8_t *>(&p2_id);
    pit.insert(pit.end(), p, p + 4);
    uint8_t p2_ip[16] = {0};
    p2_ip[0] = 0x20;
    p2_ip[1] = 0x01;
    pit.insert(pit.end(), p2_ip, p2_ip + 16);
    uint32_t p2_as = htonl(131072);
    p = reinterpret_cast<const uint8_t *>(&p2_as);
    pit.insert(pit.end(), p, p + 4);

    writeMrtRecord(1600000000, 13, 1, pit);
  }

  // 2. TableDumpV2 RIB_IPV4_UNICAST
  {
    std::vector<uint8_t> rib;
    uint32_t seq = htonl(1);
    const uint8_t *p = reinterpret_cast<const uint8_t *>(&seq);
    rib.insert(rib.end(), p, p + 4);
    rib.push_back(24);  // prefix_length
    uint8_t pfx[3] = {192, 0, 2};
    rib.insert(rib.end(), pfx, pfx + 3);
    uint16_t entry_count = htons(1);
    p = reinterpret_cast<const uint8_t *>(&entry_count);
    rib.insert(rib.end(), p, p + 2);
    uint16_t peer_idx = htons(0);
    p = reinterpret_cast<const uint8_t *>(&peer_idx);
    rib.insert(rib.end(), p, p + 2);
    uint32_t orig_time = htonl(1600000000);
    p = reinterpret_cast<const uint8_t *>(&orig_time);
    rib.insert(rib.end(), p, p + 4);
    // Attr: ORIGIN (IGP)
    uint16_t attr_len = htons(4);
    p = reinterpret_cast<const uint8_t *>(&attr_len);
    rib.insert(rib.end(), p, p + 2);
    uint8_t attr_origin[] = {0x40, 0x01, 0x01, 0x00};
    rib.insert(rib.end(), attr_origin, attr_origin + 4);

    writeMrtRecord(1600000000, 13, 2, rib);
  }

  // 3. TableDumpV2 RIB_IPV6_UNICAST
  {
    std::vector<uint8_t> rib;
    uint32_t seq = htonl(2);
    const uint8_t *p = reinterpret_cast<const uint8_t *>(&seq);
    rib.insert(rib.end(), p, p + 4);
    rib.push_back(32);  // prefix_length
    uint8_t pfx[4] = {0x20, 0x01, 0x0D, 0xB8};
    rib.insert(rib.end(), pfx, pfx + 4);
    uint16_t entry_count = htons(1);
    p = reinterpret_cast<const uint8_t *>(&entry_count);
    rib.insert(rib.end(), p, p + 2);
    uint16_t peer_idx = htons(1);
    p = reinterpret_cast<const uint8_t *>(&peer_idx);
    rib.insert(rib.end(), p, p + 2);
    uint32_t orig_time = htonl(1600000000);
    p = reinterpret_cast<const uint8_t *>(&orig_time);
    rib.insert(rib.end(), p, p + 4);
    // Attr: ORIGIN (INCOMPLETE = 2)
    uint16_t attr_len = htons(4);
    p = reinterpret_cast<const uint8_t *>(&attr_len);
    rib.insert(rib.end(), p, p + 2);
    uint8_t attr_origin[] = {0x40, 0x01, 0x01, 0x02};
    rib.insert(rib.end(), attr_origin, attr_origin + 4);

    writeMrtRecord(1600000000, 13, 4, rib);
  }

  // 4. BGP4MP_ET BGP4MP_MESSAGE_AS4 with BGP OPEN
  {
    std::vector<uint8_t> bgp4mp;
    // Peer AS, Local AS (4 bytes each)
    uint32_t peer_as = htonl(65001), local_as = htonl(65002);
    const uint8_t *p = reinterpret_cast<const uint8_t *>(&peer_as);
    bgp4mp.insert(bgp4mp.end(), p, p + 4);
    p = reinterpret_cast<const uint8_t *>(&local_as);
    bgp4mp.insert(bgp4mp.end(), p, p + 4);
    uint16_t if_index = htons(0), afi = htons(1);
    p = reinterpret_cast<const uint8_t *>(&if_index);
    bgp4mp.insert(bgp4mp.end(), p, p + 2);
    p = reinterpret_cast<const uint8_t *>(&afi);
    bgp4mp.insert(bgp4mp.end(), p, p + 2);
    uint8_t peer_ip[4] = {192, 0, 2, 1}, local_ip[4] = {192, 0, 2, 2};
    bgp4mp.insert(bgp4mp.end(), peer_ip, peer_ip + 4);
    bgp4mp.insert(bgp4mp.end(), local_ip, local_ip + 4);

    // BGP Header: 16 bytes marker, length (19 + 10 = 29), type (1 = OPEN)
    for (int i = 0; i < 16; ++i) bgp4mp.push_back(0xFF);
    uint16_t bgp_len = htons(29);
    p = reinterpret_cast<const uint8_t *>(&bgp_len);
    bgp4mp.insert(bgp4mp.end(), p, p + 2);
    bgp4mp.push_back(1);  // OPEN

    // OPEN Payload: version 4, my_as 65001, hold_time 180, bgp_id 192.0.2.1,
    // opt_param_len 0
    bgp4mp.push_back(4);
    uint16_t my_as = htons(65001), hold_time = htons(180);
    p = reinterpret_cast<const uint8_t *>(&my_as);
    bgp4mp.insert(bgp4mp.end(), p, p + 2);
    p = reinterpret_cast<const uint8_t *>(&hold_time);
    bgp4mp.insert(bgp4mp.end(), p, p + 2);
    uint32_t bgp_id = htonl(0xC0000201);
    p = reinterpret_cast<const uint8_t *>(&bgp_id);
    bgp4mp.insert(bgp4mp.end(), p, p + 4);
    bgp4mp.push_back(0);  // opt_param_len

    writeMrtRecord(1600000000, 17, 4, bgp4mp, true, 123456);
  }

  // 5. BGP4MP_ET BGP4MP_MESSAGE_AS4 with BGP UPDATE:
  //    withdrawn routes, NLRI, ORIGIN (EGP), AS_PATH (with AS_SEQUENCE and
  //    AS_SET), NEXT_HOP, MP_REACH, MP_UNREACH, COMMUNITIES (valid + invalid),
  //    Unknown attr
  {
    std::vector<uint8_t> bgp4mp;
    uint32_t peer_as = htonl(65001), local_as = htonl(65002);
    const uint8_t *p = reinterpret_cast<const uint8_t *>(&peer_as);
    bgp4mp.insert(bgp4mp.end(), p, p + 4);
    p = reinterpret_cast<const uint8_t *>(&local_as);
    bgp4mp.insert(bgp4mp.end(), p, p + 4);
    uint16_t if_index = htons(0), afi = htons(1);
    p = reinterpret_cast<const uint8_t *>(&if_index);
    bgp4mp.insert(bgp4mp.end(), p, p + 2);
    p = reinterpret_cast<const uint8_t *>(&afi);
    bgp4mp.insert(bgp4mp.end(), p, p + 2);
    uint8_t peer_ip[4] = {192, 0, 2, 1}, local_ip[4] = {192, 0, 2, 2};
    bgp4mp.insert(bgp4mp.end(), peer_ip, peer_ip + 4);
    bgp4mp.insert(bgp4mp.end(), local_ip, local_ip + 4);

    // Build UPDATE message payload
    std::vector<uint8_t> update_payload;
    // Withdrawn routes: 10.0.0.0/8 (2 bytes: len 8, byte 10)
    uint16_t withdrawn_len = htons(2);
    p = reinterpret_cast<const uint8_t *>(&withdrawn_len);
    update_payload.insert(update_payload.end(), p, p + 2);
    update_payload.push_back(8);
    update_payload.push_back(10);

    // Attributes
    std::vector<uint8_t> attrs;
    // ORIGIN = EGP (1)
    attrs.push_back(0x40);
    attrs.push_back(1);
    attrs.push_back(1);
    attrs.push_back(1);

    // AS_PATH: AS_SEQUENCE with 65001, 65002; AS_SET with 65003
    attrs.push_back(0x40);
    attrs.push_back(2);
    uint8_t as_path_val[] = {
        0x02, 0x02, 0x00, 0x00, 0xFD, 0xE9,  // 65001
        0x00, 0x00, 0xFD, 0xEA,              // 65002
        0x01, 0x01, 0x00, 0x00, 0xFD, 0xEB   // 65003
    };
    attrs.push_back(sizeof(as_path_val));
    attrs.insert(attrs.end(), as_path_val, as_path_val + sizeof(as_path_val));

    // NEXT_HOP: 192.0.2.254
    attrs.push_back(0x40);
    attrs.push_back(3);
    attrs.push_back(4);
    uint8_t nh[4] = {192, 0, 2, 254};
    attrs.insert(attrs.end(), nh, nh + 4);

    // MP_REACH_NLRI: AFI=2 (IPv6), SAFI=1, NH=16 bytes, NLRI: 2001:db8::/32
    attrs.push_back(0x50);
    attrs.push_back(14);  // extended length
    std::vector<uint8_t> mp_reach_val = {
        0x00, 0x02,  // AFI
        0x01,        // SAFI
        0x10         // NH len = 16
    };
    for (int i = 0; i < 16; ++i)
      mp_reach_val.push_back(i == 0 ? 0x20 : (i == 1 ? 0x01 : 0));
    mp_reach_val.push_back(0x00);  // reserved
    mp_reach_val.push_back(32);    // NLRI /32
    uint8_t mp_pfx[4] = {0x20, 0x01, 0x0D, 0xB8};
    mp_reach_val.insert(mp_reach_val.end(), mp_pfx, mp_pfx + 4);
    uint16_t mp_reach_len = htons(mp_reach_val.size());
    p = reinterpret_cast<const uint8_t *>(&mp_reach_len);
    attrs.insert(attrs.end(), p, p + 2);
    attrs.insert(attrs.end(), mp_reach_val.begin(), mp_reach_val.end());

    // MP_UNREACH_NLRI: AFI=2, SAFI=1, Withdrawn: 2001:db8:1::/48
    attrs.push_back(0x40);
    attrs.push_back(15);
    std::vector<uint8_t> mp_unreach_val = {
        0x00, 0x02,  // AFI
        0x01,        // SAFI
        48           // /48 (6 bytes)
    };
    uint8_t unreach_pfx[6] = {0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01};
    mp_unreach_val.insert(mp_unreach_val.end(), unreach_pfx, unreach_pfx + 6);
    attrs.push_back(mp_unreach_val.size());
    attrs.insert(attrs.end(), mp_unreach_val.begin(), mp_unreach_val.end());

    // COMMUNITIES: valid (65000:100)
    attrs.push_back(0xC0);
    attrs.push_back(8);
    attrs.push_back(4);
    uint8_t comm_val[4] = {0xFD, 0xE8, 0x00, 0x64};
    attrs.insert(attrs.end(), comm_val, comm_val + 4);

    // COMMUNITIES: invalid length (3 bytes) to trigger line 365
    attrs.push_back(0xC0);
    attrs.push_back(8);
    attrs.push_back(3);
    attrs.push_back(1);
    attrs.push_back(2);
    attrs.push_back(3);

    // Unknown attribute: type 99, len 2 to trigger line 369
    attrs.push_back(0xC0);
    attrs.push_back(99);
    attrs.push_back(2);
    attrs.push_back(0xAA);
    attrs.push_back(0xBB);

    uint16_t attr_len = htons(attrs.size());
    p = reinterpret_cast<const uint8_t *>(&attr_len);
    update_payload.insert(update_payload.end(), p, p + 2);
    update_payload.insert(update_payload.end(), attrs.begin(), attrs.end());

    // NLRI: 192.168.0.0/16
    update_payload.push_back(16);
    update_payload.push_back(192);
    update_payload.push_back(168);

    // Add BGP Header
    for (int i = 0; i < 16; ++i) bgp4mp.push_back(0xFF);
    uint16_t bgp_len = htons(19 + update_payload.size());
    p = reinterpret_cast<const uint8_t *>(&bgp_len);
    bgp4mp.insert(bgp4mp.end(), p, p + 2);
    bgp4mp.push_back(2);  // UPDATE
    bgp4mp.insert(bgp4mp.end(), update_payload.begin(), update_payload.end());

    writeMrtRecord(1600000000, 17, 4, bgp4mp, true, 654321);
  }

  // 6. BGP4MP BGP4MP_MESSAGE (2-byte AS session, IPv6 AFI = 2)
  {
    std::vector<uint8_t> bgp4mp;
    uint16_t peer_as = htons(65001), local_as = htons(65002);
    const uint8_t *p = reinterpret_cast<const uint8_t *>(&peer_as);
    bgp4mp.insert(bgp4mp.end(), p, p + 2);
    p = reinterpret_cast<const uint8_t *>(&local_as);
    bgp4mp.insert(bgp4mp.end(), p, p + 2);
    uint16_t if_index = htons(0), afi = htons(2);  // IPv6 AFI
    p = reinterpret_cast<const uint8_t *>(&if_index);
    bgp4mp.insert(bgp4mp.end(), p, p + 2);
    p = reinterpret_cast<const uint8_t *>(&afi);
    bgp4mp.insert(bgp4mp.end(), p, p + 2);
    uint8_t p_ip[16] = {0}, l_ip[16] = {0};
    bgp4mp.insert(bgp4mp.end(), p_ip, p_ip + 16);
    bgp4mp.insert(bgp4mp.end(), l_ip, l_ip + 16);

    // BGP Header
    for (int i = 0; i < 16; ++i) bgp4mp.push_back(0xFF);
    std::vector<uint8_t> upd;
    uint16_t zero = 0;
    p = reinterpret_cast<const uint8_t *>(&zero);
    upd.insert(upd.end(), p, p + 2);  // withdrawn len = 0

    // AS_PATH with 2-byte ASNs
    std::vector<uint8_t> attrs;
    attrs.push_back(0x40);
    attrs.push_back(2);  // AS_PATH
    uint8_t as2_seg[] = {0x02, 0x01, 0xFD,
                         0xE9};  // seg type 2, count 1, ASN 65001
    attrs.push_back(sizeof(as2_seg));
    attrs.insert(attrs.end(), as2_seg, as2_seg + sizeof(as2_seg));
    uint16_t attr_len = htons(attrs.size());
    p = reinterpret_cast<const uint8_t *>(&attr_len);
    upd.insert(upd.end(), p, p + 2);
    upd.insert(upd.end(), attrs.begin(), attrs.end());

    uint16_t bgp_len = htons(19 + upd.size());
    p = reinterpret_cast<const uint8_t *>(&bgp_len);
    bgp4mp.insert(bgp4mp.end(), p, p + 2);
    bgp4mp.push_back(2);  // UPDATE
    bgp4mp.insert(bgp4mp.end(), upd.begin(), upd.end());

    writeMrtRecord(1600000000, 16, 1, bgp4mp);
  }

  // 7. BGP4MP BGP4MP_MESSAGE_AS4_ADDPATH (with add-path)
  {
    std::vector<uint8_t> bgp4mp;
    uint32_t peer_as = htonl(65001), local_as = htonl(65002);
    const uint8_t *p = reinterpret_cast<const uint8_t *>(&peer_as);
    bgp4mp.insert(bgp4mp.end(), p, p + 4);
    p = reinterpret_cast<const uint8_t *>(&local_as);
    bgp4mp.insert(bgp4mp.end(), p, p + 4);
    uint16_t if_index = htons(0), afi = htons(1);
    p = reinterpret_cast<const uint8_t *>(&if_index);
    bgp4mp.insert(bgp4mp.end(), p, p + 2);
    p = reinterpret_cast<const uint8_t *>(&afi);
    bgp4mp.insert(bgp4mp.end(), p, p + 2);
    uint8_t peer_ip[4] = {192, 0, 2, 1}, local_ip[4] = {192, 0, 2, 2};
    bgp4mp.insert(bgp4mp.end(), peer_ip, peer_ip + 4);
    bgp4mp.insert(bgp4mp.end(), local_ip, local_ip + 4);

    for (int i = 0; i < 16; ++i) bgp4mp.push_back(0xFF);
    std::vector<uint8_t> upd;
    // Withdrawn with path_id: path_id = 1 (4 bytes), prefix 10.0.0.0/8
    uint8_t with_ap[] = {0x00, 0x00, 0x00, 0x01, 8, 10};
    uint16_t with_len = htons(sizeof(with_ap));
    p = reinterpret_cast<const uint8_t *>(&with_len);
    upd.insert(upd.end(), p, p + 2);
    upd.insert(upd.end(), with_ap, with_ap + sizeof(with_ap));

    uint16_t zero_attr = 0;
    p = reinterpret_cast<const uint8_t *>(&zero_attr);
    upd.insert(upd.end(), p, p + 2);

    // NLRI with path_id: path_id = 2 (4 bytes), prefix 192.168.1.0/24
    uint8_t nlri_ap[] = {0x00, 0x00, 0x00, 0x02, 24, 192, 168, 1};
    upd.insert(upd.end(), nlri_ap, nlri_ap + sizeof(nlri_ap));

    uint16_t bgp_len = htons(19 + upd.size());
    p = reinterpret_cast<const uint8_t *>(&bgp_len);
    bgp4mp.insert(bgp4mp.end(), p, p + 2);
    bgp4mp.push_back(2);
    bgp4mp.insert(bgp4mp.end(), upd.begin(), upd.end());

    writeMrtRecord(1600000000, 16, 9, bgp4mp);
  }

  out.close();
  return filepath;
}

}  // namespace

TEST(MrtParserCliTest, HelpFlags) {
  std::string bin = MRTPARSER_BIN;
  auto res1 = runCommand(bin + " -h");
  EXPECT_EQ(res1.exit_code, 0);
  EXPECT_NE(res1.stdout_str.find("Usage:"), std::string::npos);

  auto res2 = runCommand(bin + " --help");
  EXPECT_EQ(res2.exit_code, 0);
  EXPECT_NE(res2.stdout_str.find("Usage:"), std::string::npos);
}

TEST(MrtParserCliTest, NoArgumentsAndUnknownOption) {
  std::string bin = MRTPARSER_BIN;
  auto res1 = runCommand(bin);
  EXPECT_EQ(res1.exit_code, 1);
  EXPECT_NE(res1.stdout_str.find("Usage:"), std::string::npos);

  auto res2 = runCommand(bin + " --badflag");
  EXPECT_EQ(res2.exit_code, 1);
  EXPECT_NE(res2.stdout_str.find("Unknown option: --badflag"),
            std::string::npos);
}

TEST(MrtParserCliTest, NonexistentFiles) {
  std::string bin = MRTPARSER_BIN;
  auto res1 = runCommand(bin + " nonexistent_1.mrt");
  EXPECT_EQ(res1.exit_code, 0);
  EXPECT_NE(res1.stdout_str.find("Error opening file:"), std::string::npos);

  auto res2 = runCommand(bin + " nonexistent_1.mrt nonexistent_2.mrt");
  EXPECT_EQ(res2.exit_code, 0);
  EXPECT_NE(res2.stdout_str.find("Processing file: nonexistent_1.mrt"),
            std::string::npos);
  EXPECT_NE(res2.stdout_str.find("Error opening file: nonexistent_1.mrt"),
            std::string::npos);
}

TEST(MrtParserCliTest, RealDataFlags) {
  std::string bin = MRTPARSER_BIN;
  std::string file = std::string(TESTDATA_DIR) + "/updates.20260222.1530.bz2";

  // Default multi-line (triggers limit break >= 5)
  auto res1 = runCommand(bin + " " + file);
  EXPECT_EQ(res1.exit_code, 0);
  EXPECT_NE(res1.stdout_str.find("Record 1:"), std::string::npos);
  EXPECT_NE(res1.stdout_str.find("Record 5:"), std::string::npos);

  // --utc flag
  auto res2 = runCommand(bin + " --utc " + file);
  EXPECT_EQ(res2.exit_code, 0);
  EXPECT_NE(res2.stdout_str.find("2026-"), std::string::npos);

  // Use synthetic file for fast flag testing
  std::string synth_file = "/tmp/test_flags_fast.mrt";
  createSyntheticMrtFile(synth_file);

  // --single-line
  auto res3 = runCommand(bin + " --single-line " + synth_file);
  EXPECT_EQ(res3.exit_code, 0);
  EXPECT_NE(res3.stdout_str.find("Record 1: Timestamp:"), std::string::npos);

  // --singleline
  auto res4 = runCommand(bin + " --singleline " + synth_file);
  EXPECT_EQ(res4.exit_code, 0);

  // -s
  auto res5 = runCommand(bin + " -s " + synth_file);
  EXPECT_EQ(res5.exit_code, 0);

  // --json
  auto res6 = runCommand(bin + " --json " + synth_file);
  EXPECT_EQ(res6.exit_code, 0);
  EXPECT_NE(res6.stdout_str.find("\"mrt_type\":"), std::string::npos);

  // Multiple files
  auto res7 = runCommand(bin + " -s " + synth_file + " " + synth_file);
  EXPECT_EQ(res7.exit_code, 0);
  EXPECT_NE(res7.stdout_str.find("Processing file:"), std::string::npos);

  std::remove(synth_file.c_str());
}

TEST(MrtParserCliTest, SyntheticComprehensiveTest) {
  std::string bin = MRTPARSER_BIN;
  std::string synth_file = "/tmp/test_synthetic_cli.mrt";
  createSyntheticMrtFile(synth_file);

  // 1. Run with --json: exercises every to_json serializer
  auto json_res = runCommand(bin + " --json " + synth_file);
  EXPECT_EQ(json_res.exit_code, 0);
  EXPECT_NE(json_res.stdout_str.find("\"peer_index_table\":"),
            std::string::npos);
  EXPECT_NE(json_res.stdout_str.find("\"rib_record\":"), std::string::npos);
  EXPECT_NE(json_res.stdout_str.find("\"microsecond_timestamp\":123456"),
            std::string::npos);

  // 2. Run with --single-line --utc: exercises single-line display of all
  // records and attributes
  auto single_res = runCommand(bin + " --single-line --utc " + synth_file);
  EXPECT_EQ(single_res.exit_code, 0);
  EXPECT_NE(single_res.stdout_str.find("Record 1:"), std::string::npos);
  EXPECT_NE(single_res.stdout_str.find("BGPType: OPEN"), std::string::npos);
  EXPECT_NE(single_res.stdout_str.find("BGPType: UPDATE"), std::string::npos);
  EXPECT_NE(single_res.stdout_str.find("Withdrawn:"), std::string::npos);
  EXPECT_NE(single_res.stdout_str.find("NLRI:"), std::string::npos);
  EXPECT_NE(single_res.stdout_str.find("ORIGIN=EGP"), std::string::npos);
  EXPECT_NE(single_res.stdout_str.find("AS_PATH="), std::string::npos);
  EXPECT_NE(single_res.stdout_str.find("NEXT_HOP=192.0.2.254"),
            std::string::npos);
  EXPECT_NE(single_res.stdout_str.find("MP_REACH_NLRI=2"), std::string::npos);
  EXPECT_NE(single_res.stdout_str.find("MP_UNREACH_NLRI=2"), std::string::npos);
  EXPECT_NE(single_res.stdout_str.find("COMMUNITIES=65000:100"),
            std::string::npos);
  EXPECT_NE(single_res.stdout_str.find("RIB: 192.0.2.0/24"), std::string::npos);

  // 3. Run with default multi-line: exercises multi-line display of all records
  // and attributes
  auto multi_res = runCommand(bin + " " + synth_file);
  EXPECT_EQ(multi_res.exit_code, 0);
  EXPECT_NE(multi_res.stdout_str.find("    BGP Type: OPEN"), std::string::npos);
  EXPECT_NE(multi_res.stdout_str.find("    BGP Type: UPDATE"),
            std::string::npos);
  EXPECT_NE(multi_res.stdout_str.find("      Withdrawn (1):"),
            std::string::npos);
  EXPECT_NE(multi_res.stdout_str.find("      NLRI (1):"), std::string::npos);
  EXPECT_NE(multi_res.stdout_str.find("ORIGIN=EGP"), std::string::npos);
  EXPECT_NE(multi_res.stdout_str.find("AS_PATH="), std::string::npos);
  EXPECT_NE(multi_res.stdout_str.find("NEXT_HOP=192.0.2.254"),
            std::string::npos);
  EXPECT_NE(multi_res.stdout_str.find("MP_REACH AFI=2"), std::string::npos);
  EXPECT_NE(multi_res.stdout_str.find("MP_UNREACH AFI=2"), std::string::npos);
  EXPECT_NE(multi_res.stdout_str.find("COMMUNITIES=65000:100"),
            std::string::npos);
  EXPECT_NE(multi_res.stdout_str.find("    RIB Prefix: 192.0.2.0/24"),
            std::string::npos);
  EXPECT_NE(multi_res.stdout_str.find("    RIB Prefix: 2001:db8::/32"),
            std::string::npos);

  std::remove(synth_file.c_str());
}
