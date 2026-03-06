#include "mrt_parser.h"
#include <gtest/gtest.h>
#include "bgp_parser.h"

TEST(MrtParserTest, BasicInitialization) {
  mrt::MrtRecord record;
  EXPECT_FALSE(record.has_et);
  EXPECT_EQ(record.microsecond_timestamp, 0);
}

// TODO: Add more tests for parsing binary data
