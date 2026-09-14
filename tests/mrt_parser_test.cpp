#include "mrt_parser.h"
#include <arpa/inet.h>
#include <cstdio>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
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

  // Helper lambda to write a record in MRT binary format
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

  // Now verify raw parser
  mrt::MrtParser raw_parser(raw_tmp);
  ASSERT_TRUE(raw_parser.isOpen());
  int raw_count = 0;
  mrt::MrtRecord raw_rec;
  while (raw_parser.nextRecord(raw_rec)) {
    raw_count++;
    EXPECT_GT(raw_rec.header.timestamp, 0);
  }
  EXPECT_EQ(raw_count, 5);

  // Verify gz parser
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
