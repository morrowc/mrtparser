#include "mrt_parser.h"
#include <arpa/inet.h>
#include <cstdio>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <zlib.h>
#include "bgp_parser.h"

TEST(MrtParserTest, BasicInitialization) {
  mrt::MrtRecord record;
  EXPECT_FALSE(record.has_et);
  EXPECT_EQ(record.microsecond_timestamp, 0);
}

TEST(MrtParserTest, NonexistentFile) {
  mrt::MrtParser parser("nonexistent_path_12345.mrt");
  EXPECT_FALSE(parser.isOpen());
  mrt::MrtRecord record;
  EXPECT_FALSE(parser.nextRecord(record));
}

TEST(MrtParserTest, NonexistentBz2File) {
  mrt::MrtParser parser("nonexistent_path_12345.bz2");
  EXPECT_FALSE(parser.isOpen());
  mrt::MrtRecord record;
  EXPECT_FALSE(parser.nextRecord(record));
}

TEST(MrtParserTest, NonexistentGzFile) {
  mrt::MrtParser parser("nonexistent_path_12345.gz");
  EXPECT_FALSE(parser.isOpen());
  mrt::MrtRecord record;
  EXPECT_FALSE(parser.nextRecord(record));
}

TEST(MrtParserTest, CorruptBz2File) {
  std::string corrupt_path = "/tmp/test_corrupt.bz2";
  std::ofstream out(corrupt_path, std::ios::binary);
  out << "This is not a valid bzip2 file content!";
  out.close();

  mrt::MrtParser parser(corrupt_path);
  EXPECT_TRUE(parser.isOpen());
  mrt::MrtRecord record;
  EXPECT_FALSE(parser.nextRecord(record));
  std::remove(corrupt_path.c_str());
}

TEST(MrtParserTest, ParseBz2File) {
  std::string path = "testdata/updates.20260222.1530.bz2";
  if (!std::ifstream(path).is_open()) {
    path = "../testdata/updates.20260222.1530.bz2";
  }
  mrt::MrtParser parser(path);
  ASSERT_TRUE(parser.isOpen());
  mrt::MrtRecord record;
  int count = 0;
  while (parser.nextRecord(record) && count < 10) {
    count++;
    EXPECT_GT(record.header.timestamp, 0);
    EXPECT_GT(record.header.length, 0);
  }
  EXPECT_EQ(count, 10);
}

TEST(MrtParserTest, ParseGzAndRawFiles) {
  std::string bz2_path = "testdata/updates.20260222.1530.bz2";
  if (!std::ifstream(bz2_path).is_open()) {
    bz2_path = "../testdata/updates.20260222.1530.bz2";
  }

  // Create temporary gz and raw files from the first 5 records of bz2_path
  std::string raw_tmp = "/tmp/test_mrt_temp.mrt";
  std::string gz_tmp = "/tmp/test_mrt_temp.gz";

  std::ofstream raw_out(raw_tmp, std::ios::binary);
  gzFile gz_out = gzopen(gz_tmp.c_str(), "wb");
  ASSERT_NE(gz_out, nullptr);

  mrt::MrtParser bz2_parser(bz2_path);
  ASSERT_TRUE(bz2_parser.isOpen());

  auto writeRecord = [&](const mrt::MrtRecord &rec, std::ostream &raw,
                         gzFile gz) {
    uint32_t ts = htonl(rec.header.timestamp);
    uint16_t type = htons(rec.header.type);
    uint16_t subtype = htons(rec.header.subtype);
    uint32_t len = htonl(rec.header.length);

    raw.write(reinterpret_cast<const char *>(&ts), 4);
    raw.write(reinterpret_cast<const char *>(&type), 2);
    raw.write(reinterpret_cast<const char *>(&subtype), 2);
    raw.write(reinterpret_cast<const char *>(&len), 4);

    gzwrite(gz, &ts, 4);
    gzwrite(gz, &type, 2);
    gzwrite(gz, &subtype, 2);
    gzwrite(gz, &len, 4);

    if (rec.has_et) {
      uint32_t micro = htonl(rec.microsecond_timestamp);
      raw.write(reinterpret_cast<const char *>(&micro), 4);
      gzwrite(gz, &micro, 4);
    }

    raw.write(reinterpret_cast<const char *>(rec.message.data()),
              rec.message.size());
    gzwrite(gz, rec.message.data(), rec.message.size());
  };

  mrt::MrtRecord orig_rec;
  int written = 0;
  while (bz2_parser.nextRecord(orig_rec) && written < 5) {
    writeRecord(orig_rec, raw_out, gz_out);
    written++;
  }
  raw_out.close();
  gzclose(gz_out);
  ASSERT_EQ(written, 5);

  mrt::MrtParser raw_parser(raw_tmp);
  ASSERT_TRUE(raw_parser.isOpen());
  int raw_count = 0;
  mrt::MrtRecord raw_rec;
  while (raw_parser.nextRecord(raw_rec)) {
    raw_count++;
    EXPECT_GT(raw_rec.header.timestamp, 0);
  }
  EXPECT_EQ(raw_count, 5);

  mrt::MrtParser gz_parser(gz_tmp);
  ASSERT_TRUE(gz_parser.isOpen());
  int gz_count = 0;
  mrt::MrtRecord gz_rec;
  while (gz_parser.nextRecord(gz_rec)) {
    gz_count++;
    EXPECT_GT(gz_rec.header.timestamp, 0);
  }
  EXPECT_EQ(gz_count, 5);

  std::remove(raw_tmp.c_str());
  std::remove(gz_tmp.c_str());
}

TEST(MrtParserTest, TruncatedRecordHandling) {
  // Truncated header (< 12 bytes)
  std::string trunc_hdr_path = "/tmp/test_trunc_hdr.mrt";
  std::ofstream out1(trunc_hdr_path, std::ios::binary);
  uint8_t short_bytes[] = {0x00, 0x01, 0x02, 0x03, 0x04};
  out1.write(reinterpret_cast<char *>(short_bytes), sizeof(short_bytes));
  out1.close();

  mrt::MrtParser p1(trunc_hdr_path);
  mrt::MrtRecord rec1;
  EXPECT_FALSE(p1.nextRecord(rec1));
  std::remove(trunc_hdr_path.c_str());

  // Truncated ET (< 4 bytes of microsecond timestamp)
  std::string trunc_et_path = "/tmp/test_trunc_et.mrt";
  std::ofstream out2(trunc_et_path, std::ios::binary);
  uint32_t ts = htonl(1600000000);
  uint16_t type = htons(static_cast<uint16_t>(mrt::MrtType::BGP4MP_ET));
  uint16_t subtype = htons(4);
  uint32_t len = htonl(10);
  out2.write(reinterpret_cast<char *>(&ts), 4);
  out2.write(reinterpret_cast<char *>(&type), 2);
  out2.write(reinterpret_cast<char *>(&subtype), 2);
  out2.write(reinterpret_cast<char *>(&len), 4);
  uint16_t partial_micro = htons(1234);
  out2.write(reinterpret_cast<char *>(&partial_micro),
             2);  // only 2 bytes instead of 4
  out2.close();

  mrt::MrtParser p2(trunc_et_path);
  mrt::MrtRecord rec2;
  EXPECT_FALSE(p2.nextRecord(rec2));
  std::remove(trunc_et_path.c_str());

  // Truncated message body
  std::string trunc_msg_path = "/tmp/test_trunc_msg.mrt";
  std::ofstream out3(trunc_msg_path, std::ios::binary);
  type = htons(static_cast<uint16_t>(mrt::MrtType::BGP4MP));
  len = htonl(20);
  out3.write(reinterpret_cast<char *>(&ts), 4);
  out3.write(reinterpret_cast<char *>(&type), 2);
  out3.write(reinterpret_cast<char *>(&subtype), 2);
  out3.write(reinterpret_cast<char *>(&len), 4);
  uint8_t short_msg[5] = {1, 2, 3, 4, 5};
  out3.write(reinterpret_cast<char *>(short_msg), 5);  // 5 bytes instead of 20
  out3.close();

  mrt::MrtParser p3(trunc_msg_path);
  mrt::MrtRecord rec3;
  EXPECT_FALSE(p3.nextRecord(rec3));
  std::remove(trunc_msg_path.c_str());
}

TEST(MrtParserTest, ExtendedTimestampTypes) {
  // Test ISIS_ET and OSPFv3_ET
  auto testEtType = [](mrt::MrtType mrt_type) {
    std::string path = "/tmp/test_et_type.mrt";
    std::ofstream out(path, std::ios::binary);
    uint32_t ts = htonl(1600000000);
    uint16_t type = htons(static_cast<uint16_t>(mrt_type));
    uint16_t subtype = htons(0);
    uint32_t len = htonl(8);  // 4 bytes microsec + 4 bytes message
    uint32_t micro = htonl(987654);
    uint32_t msg = htonl(0xAABBCCDD);

    out.write(reinterpret_cast<char *>(&ts), 4);
    out.write(reinterpret_cast<char *>(&type), 2);
    out.write(reinterpret_cast<char *>(&subtype), 2);
    out.write(reinterpret_cast<char *>(&len), 4);
    out.write(reinterpret_cast<char *>(&micro), 4);
    out.write(reinterpret_cast<char *>(&msg), 4);
    out.close();

    mrt::MrtParser parser(path);
    mrt::MrtRecord rec;
    EXPECT_TRUE(parser.nextRecord(rec));
    EXPECT_TRUE(rec.has_et);
    EXPECT_EQ(rec.microsecond_timestamp, 987654);
    ASSERT_EQ(rec.message.size(), 4);
    std::remove(path.c_str());
  };

  testEtType(mrt::MrtType::ISIS_ET);
  testEtType(mrt::MrtType::OSPFv3_ET);
}

TEST(MrtParserTest, ParseTableDumpV2_PeerIndexTable) {
  std::string path = "/tmp/test_table_dump_v2_pit.mrt";
  std::ofstream out(path, std::ios::binary);

  // 1. PIT with size < 4
  uint32_t ts = htonl(1600000000);
  uint16_t type = htons(static_cast<uint16_t>(mrt::MrtType::TABLE_DUMP_V2));
  uint16_t subtype =
      htons(static_cast<uint16_t>(mrt::TableDumpV2Subtype::PEER_INDEX_TABLE));
  uint32_t len = htonl(2);
  out.write(reinterpret_cast<char *>(&ts), 4);
  out.write(reinterpret_cast<char *>(&type), 2);
  out.write(reinterpret_cast<char *>(&subtype), 2);
  out.write(reinterpret_cast<char *>(&len), 4);
  uint16_t short_pit = 0;
  out.write(reinterpret_cast<char *>(&short_pit), 2);

  // 2. PIT with view_name_len exceeding size
  len = htonl(6);
  out.write(reinterpret_cast<char *>(&ts), 4);
  out.write(reinterpret_cast<char *>(&type), 2);
  out.write(reinterpret_cast<char *>(&subtype), 2);
  out.write(reinterpret_cast<char *>(&len), 4);
  uint32_t bgp_id = htonl(0x01020304);
  uint16_t invalid_view_len = htons(10);
  out.write(reinterpret_cast<char *>(&bgp_id), 4);
  out.write(reinterpret_cast<char *>(&invalid_view_len), 2);

  // 3. Valid PIT with IPv4 2-byte AS, IPv4 4-byte AS, IPv6 2-byte AS, IPv6
  // 4-byte AS
  std::vector<uint8_t> pit_payload;
  uint32_t coll_id = htonl(0xC0000201);  // 192.0.2.1
  const uint8_t *p = reinterpret_cast<const uint8_t *>(&coll_id);
  pit_payload.insert(pit_payload.end(), p, p + 4);
  uint16_t vlen = htons(4);
  p = reinterpret_cast<const uint8_t *>(&vlen);
  pit_payload.insert(pit_payload.end(), p, p + 2);
  pit_payload.push_back('t');
  pit_payload.push_back('e');
  pit_payload.push_back('s');
  pit_payload.push_back('t');

  uint16_t peer_count = htons(4);
  p = reinterpret_cast<const uint8_t *>(&peer_count);
  pit_payload.insert(pit_payload.end(), p, p + 2);

  // Peer 1: IPv4, 2-byte AS (type = 0)
  pit_payload.push_back(0);  // peer_type
  uint32_t p1_id = htonl(0x0A000001);
  p = reinterpret_cast<const uint8_t *>(&p1_id);
  pit_payload.insert(pit_payload.end(), p, p + 4);
  uint8_t p1_ip[4] = {10, 0, 0, 1};
  pit_payload.insert(pit_payload.end(), p1_ip, p1_ip + 4);
  uint16_t p1_as = htons(65001);
  p = reinterpret_cast<const uint8_t *>(&p1_as);
  pit_payload.insert(pit_payload.end(), p, p + 2);

  // Peer 2: IPv4, 4-byte AS (type = 2)
  pit_payload.push_back(2);  // peer_type
  uint32_t p2_id = htonl(0x0A000002);
  p = reinterpret_cast<const uint8_t *>(&p2_id);
  pit_payload.insert(pit_payload.end(), p, p + 4);
  uint8_t p2_ip[4] = {10, 0, 0, 2};
  pit_payload.insert(pit_payload.end(), p2_ip, p2_ip + 4);
  uint32_t p2_as = htonl(131072);
  p = reinterpret_cast<const uint8_t *>(&p2_as);
  pit_payload.insert(pit_payload.end(), p, p + 4);

  // Peer 3: IPv6, 2-byte AS (type = 1)
  pit_payload.push_back(1);  // peer_type
  uint32_t p3_id = htonl(0x0A000003);
  p = reinterpret_cast<const uint8_t *>(&p3_id);
  pit_payload.insert(pit_payload.end(), p, p + 4);
  uint8_t p3_ip[16] = {0};
  p3_ip[0] = 0x20;
  p3_ip[1] = 0x01;
  pit_payload.insert(pit_payload.end(), p3_ip, p3_ip + 16);
  uint16_t p3_as = htons(65003);
  p = reinterpret_cast<const uint8_t *>(&p3_as);
  pit_payload.insert(pit_payload.end(), p, p + 2);

  // Peer 4: IPv6, 4-byte AS (type = 3)
  pit_payload.push_back(3);  // peer_type
  uint32_t p4_id = htonl(0x0A000004);
  p = reinterpret_cast<const uint8_t *>(&p4_id);
  pit_payload.insert(pit_payload.end(), p, p + 4);
  uint8_t p4_ip[16] = {0};
  p4_ip[0] = 0x20;
  p4_ip[1] = 0x02;
  pit_payload.insert(pit_payload.end(), p4_ip, p4_ip + 16);
  uint32_t p4_as = htonl(131074);
  p = reinterpret_cast<const uint8_t *>(&p4_as);
  pit_payload.insert(pit_payload.end(), p, p + 4);

  len = htonl(pit_payload.size());
  out.write(reinterpret_cast<char *>(&ts), 4);
  out.write(reinterpret_cast<char *>(&type), 2);
  out.write(reinterpret_cast<char *>(&subtype), 2);
  out.write(reinterpret_cast<char *>(&len), 4);
  out.write(reinterpret_cast<char *>(pit_payload.data()), pit_payload.size());

  // 4. PIT with truncated peer entries to trigger breaks
  auto writeTruncatedPit = [&](const std::vector<uint8_t> &prefix_bytes) {
    len = htonl(prefix_bytes.size());
    out.write(reinterpret_cast<char *>(&ts), 4);
    out.write(reinterpret_cast<char *>(&type), 2);
    out.write(reinterpret_cast<char *>(&subtype), 2);
    out.write(reinterpret_cast<char *>(&len), 4);
    out.write(reinterpret_cast<const char *>(prefix_bytes.data()),
              prefix_bytes.size());
  };

  // Base PIT with count = 2
  std::vector<uint8_t> base_pit;
  base_pit.insert(base_pit.end(), p, p + 4);  // bgp id
  uint16_t zero_vlen = 0;
  p = reinterpret_cast<const uint8_t *>(&zero_vlen);
  base_pit.insert(base_pit.end(), p, p + 2);
  uint16_t c2 = htons(2);
  p = reinterpret_cast<const uint8_t *>(&c2);
  base_pit.insert(base_pit.end(), p, p + 2);

  // Truncated at peer_type
  writeTruncatedPit(base_pit);

  // Truncated at peer_bgp_id
  std::vector<uint8_t> t2 = base_pit;
  t2.push_back(0);  // peer_type
  t2.push_back(1);  // partial bgp id
  writeTruncatedPit(t2);

  // Truncated at IPv4 peer_ip
  std::vector<uint8_t> t3 = base_pit;
  t3.push_back(0);                              // IPv4
  for (int i = 0; i < 4; ++i) t3.push_back(0);  // bgp id
  t3.push_back(10);                             // partial ip
  writeTruncatedPit(t3);

  // Truncated at IPv6 peer_ip
  std::vector<uint8_t> t4 = base_pit;
  t4.push_back(1);                              // IPv6
  for (int i = 0; i < 4; ++i) t4.push_back(0);  // bgp id
  for (int i = 0; i < 8; ++i)
    t4.push_back(0);  // partial ipv6 (8 bytes instead of 16)
  writeTruncatedPit(t4);

  // Truncated at 2-byte peer_as
  std::vector<uint8_t> t5 = base_pit;
  t5.push_back(0);                              // IPv4, 2-byte AS
  for (int i = 0; i < 4; ++i) t5.push_back(0);  // bgp id
  for (int i = 0; i < 4; ++i) t5.push_back(0);  // ipv4
  t5.push_back(1);                              // 1 byte AS instead of 2
  writeTruncatedPit(t5);

  // Truncated at 4-byte peer_as
  std::vector<uint8_t> t6 = base_pit;
  t6.push_back(2);                              // IPv4, 4-byte AS
  for (int i = 0; i < 4; ++i) t6.push_back(0);  // bgp id
  for (int i = 0; i < 4; ++i) t6.push_back(0);  // ipv4
  t6.push_back(1);
  t6.push_back(2);  // 2 bytes AS instead of 4
  writeTruncatedPit(t6);

  out.close();

  mrt::MrtParser parser(path);
  mrt::MrtRecord rec;

  // 1. size < 4
  ASSERT_TRUE(parser.nextRecord(rec));
  ASSERT_NE(rec.peer_index_table, nullptr);
  EXPECT_TRUE(rec.peer_index_table->peers.empty());

  // 2. view_name_len exceeding
  ASSERT_TRUE(parser.nextRecord(rec));
  ASSERT_NE(rec.peer_index_table, nullptr);

  // 3. Valid PIT
  ASSERT_TRUE(parser.nextRecord(rec));
  ASSERT_NE(rec.peer_index_table, nullptr);
  EXPECT_EQ(rec.peer_index_table->view_name, "test");
  ASSERT_EQ(rec.peer_index_table->peers.size(), 4);
  EXPECT_EQ(rec.peer_index_table->peers[0].peer_ip, "10.0.0.1");
  EXPECT_EQ(rec.peer_index_table->peers[0].peer_as, 65001);
  EXPECT_EQ(rec.peer_index_table->peers[1].peer_ip, "10.0.0.2");
  EXPECT_EQ(rec.peer_index_table->peers[1].peer_as, 131072);
  EXPECT_EQ(rec.peer_index_table->peers[2].peer_ip, "IPv6...");
  EXPECT_EQ(rec.peer_index_table->peers[2].peer_as, 65003);
  EXPECT_EQ(rec.peer_index_table->peers[3].peer_ip, "IPv6...");
  EXPECT_EQ(rec.peer_index_table->peers[3].peer_as, 131074);

  // 4. Truncated cases
  for (int i = 0; i < 6; ++i) {
    ASSERT_TRUE(parser.nextRecord(rec));
    ASSERT_NE(rec.peer_index_table, nullptr);
  }

  std::remove(path.c_str());
}

TEST(MrtParserTest, ParseTableDumpV2_RibRecords) {
  std::string path = "/tmp/test_table_dump_v2_rib.mrt";
  std::ofstream out(path, std::ios::binary);

  uint32_t ts = htonl(1600000000);
  uint16_t type = htons(static_cast<uint16_t>(mrt::MrtType::TABLE_DUMP_V2));
  uint16_t subtype =
      htons(static_cast<uint16_t>(mrt::TableDumpV2Subtype::RIB_IPV4_UNICAST));

  auto writeRib = [&](const std::vector<uint8_t> &data) {
    uint32_t len = htonl(data.size());
    out.write(reinterpret_cast<char *>(&ts), 4);
    out.write(reinterpret_cast<char *>(&type), 2);
    out.write(reinterpret_cast<char *>(&subtype), 2);
    out.write(reinterpret_cast<char *>(&len), 4);
    out.write(reinterpret_cast<const char *>(data.data()), data.size());
  };

  // 1. size < 4
  writeRib({0x00, 0x01});

  // 2. offset + 1 > size (no prefix length)
  writeRib({0x00, 0x00, 0x00, 0x01});

  // 3. offset + prefix_bytes > size
  writeRib({0x00, 0x00, 0x00, 0x01, 24,
            192});  // len=24 needs 3 bytes, only 1 provided

  // 4. offset + 2 > size (no entry_count)
  writeRib({0x00, 0x00, 0x00, 0x01, 24, 192, 0, 2,
            0x01});  // only 1 byte of entry_count

  // 5. Valid RIB with 1 entry and attributes
  std::vector<uint8_t> valid_rib;
  uint32_t seq = htonl(100);
  const uint8_t *p = reinterpret_cast<const uint8_t *>(&seq);
  valid_rib.insert(valid_rib.end(), p, p + 4);
  valid_rib.push_back(24);  // /24
  valid_rib.push_back(192);
  valid_rib.push_back(0);
  valid_rib.push_back(2);
  uint16_t entry_count = htons(1);
  p = reinterpret_cast<const uint8_t *>(&entry_count);
  valid_rib.insert(valid_rib.end(), p, p + 2);
  // Entry: peer_index = 1, orig_time = 1600000000
  uint16_t peer_idx = htons(1);
  p = reinterpret_cast<const uint8_t *>(&peer_idx);
  valid_rib.insert(valid_rib.end(), p, p + 2);
  uint32_t orig_time = htonl(1600000000);
  p = reinterpret_cast<const uint8_t *>(&orig_time);
  valid_rib.insert(valid_rib.end(), p, p + 4);
  // Attributes: ORIGIN = IGP (4 bytes: 0x40, 0x01, 0x01, 0x00)
  uint16_t attr_len = htons(4);
  p = reinterpret_cast<const uint8_t *>(&attr_len);
  valid_rib.insert(valid_rib.end(), p, p + 2);
  uint8_t attr_bytes[] = {0x40, 0x01, 0x01, 0x00};
  valid_rib.insert(valid_rib.end(), attr_bytes, attr_bytes + 4);
  writeRib(valid_rib);

  // 6. Truncated entries:
  // Base header up to entry_count = 2
  std::vector<uint8_t> base_entry;
  base_entry.insert(base_entry.end(), p, p + 4);  // seq
  base_entry.push_back(0);                        // /0
  uint16_t e2 = htons(2);
  p = reinterpret_cast<const uint8_t *>(&e2);
  base_entry.insert(base_entry.end(), p, p + 2);

  // Truncated at peer_index / orig_time
  std::vector<uint8_t> tr1 = base_entry;
  tr1.push_back(0);
  tr1.push_back(1);  // 2 bytes instead of 6
  writeRib(tr1);

  // Truncated at attr_len
  std::vector<uint8_t> tr2 = base_entry;
  for (int i = 0; i < 6; ++i) tr2.push_back(0);
  tr2.push_back(0);  // 1 byte attr_len instead of 2
  writeRib(tr2);

  // Truncated at attribute content
  std::vector<uint8_t> tr3 = base_entry;
  for (int i = 0; i < 6; ++i) tr3.push_back(0);
  uint16_t large_attr = htons(20);
  p = reinterpret_cast<const uint8_t *>(&large_attr);
  tr3.insert(tr3.end(), p, p + 2);
  tr3.push_back(0x40);  // 1 byte instead of 20
  writeRib(tr3);

  out.close();

  mrt::MrtParser parser(path);
  mrt::MrtRecord rec;

  // 1-4. truncated headers
  for (int i = 0; i < 4; ++i) {
    ASSERT_TRUE(parser.nextRecord(rec));
    ASSERT_NE(rec.rib_record, nullptr);
  }

  // 5. Valid RIB
  ASSERT_TRUE(parser.nextRecord(rec));
  ASSERT_NE(rec.rib_record, nullptr);
  EXPECT_EQ(rec.rib_record->sequence_number, 100);
  EXPECT_EQ(rec.rib_record->prefix_length, 24);
  ASSERT_EQ(rec.rib_record->prefix.size(), 3);
  ASSERT_EQ(rec.rib_record->entries.size(), 1);
  EXPECT_EQ(rec.rib_record->entries[0].peer_index, 1);
  EXPECT_EQ(rec.rib_record->entries[0].originated_time, 1600000000);
  ASSERT_EQ(rec.rib_record->entries[0].attributes.size(), 1);

  // 6. Truncated entries
  for (int i = 0; i < 3; ++i) {
    ASSERT_TRUE(parser.nextRecord(rec));
    ASSERT_NE(rec.rib_record, nullptr);
  }

  std::remove(path.c_str());
}

TEST(MrtParserTest, TypeAndSubtypeToString) {
  // typeToString
  EXPECT_EQ(mrt::MrtParser::typeToString(11), "OSPFv2");
  EXPECT_EQ(mrt::MrtParser::typeToString(12), "TABLE_DUMP");
  EXPECT_EQ(mrt::MrtParser::typeToString(13), "TABLE_DUMP_V2");
  EXPECT_EQ(mrt::MrtParser::typeToString(16), "BGP4MP");
  EXPECT_EQ(mrt::MrtParser::typeToString(17), "BGP4MP_ET");
  EXPECT_EQ(mrt::MrtParser::typeToString(32), "ISIS");
  EXPECT_EQ(mrt::MrtParser::typeToString(33), "ISIS_ET");
  EXPECT_EQ(mrt::MrtParser::typeToString(48), "OSPFv3");
  EXPECT_EQ(mrt::MrtParser::typeToString(49), "OSPFv3_ET");
  EXPECT_EQ(mrt::MrtParser::typeToString(99), "UNKNOWN(99)");

  // subtypeToString TABLE_DUMP_V2
  EXPECT_EQ(mrt::MrtParser::subtypeToString(13, 1), "PEER_INDEX_TABLE");
  EXPECT_EQ(mrt::MrtParser::subtypeToString(13, 2), "RIB_IPV4_UNICAST");
  EXPECT_EQ(mrt::MrtParser::subtypeToString(13, 3), "RIB_IPV4_MULTICAST");
  EXPECT_EQ(mrt::MrtParser::subtypeToString(13, 4), "RIB_IPV6_UNICAST");
  EXPECT_EQ(mrt::MrtParser::subtypeToString(13, 5), "RIB_IPV6_MULTICAST");
  EXPECT_EQ(mrt::MrtParser::subtypeToString(13, 6), "RIB_GENERIC");
  EXPECT_EQ(mrt::MrtParser::subtypeToString(13, 8), "RIB_IPV4_UNICAST_ADDPATH");
  EXPECT_EQ(mrt::MrtParser::subtypeToString(13, 9),
            "RIB_IPV4_MULTICAST_ADDPATH");
  EXPECT_EQ(mrt::MrtParser::subtypeToString(13, 10),
            "RIB_IPV6_UNICAST_ADDPATH");
  EXPECT_EQ(mrt::MrtParser::subtypeToString(13, 11),
            "RIB_IPV6_MULTICAST_ADDPATH");
  EXPECT_EQ(mrt::MrtParser::subtypeToString(13, 12), "RIB_GENERIC_ADDPATH");
  EXPECT_EQ(mrt::MrtParser::subtypeToString(13, 99), "99");

  // subtypeToString BGP4MP & BGP4MP_ET
  for (uint16_t t : {16, 17}) {
    EXPECT_EQ(mrt::MrtParser::subtypeToString(t, 0), "BGP4MP_STATE_CHANGE");
    EXPECT_EQ(mrt::MrtParser::subtypeToString(t, 1), "BGP4MP_MESSAGE");
    EXPECT_EQ(mrt::MrtParser::subtypeToString(t, 4), "BGP4MP_MESSAGE_AS4");
    EXPECT_EQ(mrt::MrtParser::subtypeToString(t, 5), "BGP4MP_STATE_CHANGE_AS4");
    EXPECT_EQ(mrt::MrtParser::subtypeToString(t, 6), "BGP4MP_MESSAGE_LOCAL");
    EXPECT_EQ(mrt::MrtParser::subtypeToString(t, 7),
              "BGP4MP_MESSAGE_AS4_LOCAL");
    EXPECT_EQ(mrt::MrtParser::subtypeToString(t, 8), "BGP4MP_MESSAGE_ADDPATH");
    EXPECT_EQ(mrt::MrtParser::subtypeToString(t, 9),
              "BGP4MP_MESSAGE_AS4_ADDPATH");
    EXPECT_EQ(mrt::MrtParser::subtypeToString(t, 10),
              "BGP4MP_MESSAGE_LOCAL_ADDPATH");
    EXPECT_EQ(mrt::MrtParser::subtypeToString(t, 11),
              "BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH");
    EXPECT_EQ(mrt::MrtParser::subtypeToString(t, 99), "99");
  }

  // subtypeToString for other type
  EXPECT_EQ(mrt::MrtParser::subtypeToString(11, 5), "5");
}
