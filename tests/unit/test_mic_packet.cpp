/**
 * @file tests/unit/test_mic_packet.cpp
 * @brief Test src/mic_packet.*
 */
#include "../tests_common.h"

#include <src/mic_packet.h>

namespace {
  // Vectors were produced by an independent implementation of the wire format
  // (Python `cryptography` AESGCM) with key A0..AF.
  crypto::aes_t test_key() {
    crypto::aes_t key(16);
    for (int i = 0; i < 16; ++i) {
      key[i] = static_cast<std::uint8_t>(0xA0 + i);
    }
    return key;
  }

  std::string from_hex(std::string_view hex) {
    std::string out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
      out.push_back(static_cast<char>(std::stoi(std::string {hex.substr(i, 2)}, nullptr, 16)));
    }
    return out;
  }

  // counter 7, timestamp 6720, Opus bytes 01..14
  const std::string vector_a = from_hex("026100000700000040266728588653ec514592ae5be7670eb5f94d2c95303b33588ae87843efea0372a57e01c360d43d");
  // counter 0x01020304, timestamp 0xDEADBEEF, Opus bytes FC FF FE
  const std::string vector_b = from_hex("0261000004030201c76173b512768b7fca1c9d2b76200487bf913be504bad9");
}  // namespace

TEST(MicPacketTests, OpensReferenceVectors) {
  crypto::cipher::gcm_t cipher {test_key(), false};

  auto a = stream::mic::open_packet(cipher, vector_a);
  ASSERT_TRUE(a);
  EXPECT_EQ(a->counter, 7u);
  EXPECT_EQ(a->timestamp, 6720u);
  std::vector<std::uint8_t> expected_opus;
  for (int i = 1; i <= 20; ++i) {
    expected_opus.push_back(static_cast<std::uint8_t>(i));
  }
  EXPECT_EQ(a->opus, expected_opus);

  auto b = stream::mic::open_packet(cipher, vector_b);
  ASSERT_TRUE(b);
  EXPECT_EQ(b->counter, 0x01020304u);
  EXPECT_EQ(b->timestamp, 0xDEADBEEFu);
  EXPECT_EQ(b->opus, (std::vector<std::uint8_t> {0xFC, 0xFF, 0xFE}));
}

TEST(MicPacketTests, RejectsWrongKey) {
  auto key = test_key();
  key[0] ^= 1;
  crypto::cipher::gcm_t cipher {key, false};
  EXPECT_FALSE(stream::mic::open_packet(cipher, vector_a));
}

TEST(MicPacketTests, RejectsTampering) {
  crypto::cipher::gcm_t cipher {test_key(), false};

  // Every byte of the counter, tag, and ciphertext is authenticated
  for (std::size_t i = 4; i < vector_a.size(); ++i) {
    auto tampered = vector_a;
    tampered[i] ^= 0x01;
    EXPECT_FALSE(stream::mic::open_packet(cipher, tampered)) << "byte " << i;
  }

  // The untouched packet still opens afterwards
  EXPECT_TRUE(stream::mic::open_packet(cipher, vector_a));
}

TEST(MicPacketTests, RejectsWrongVersionOrType) {
  crypto::cipher::gcm_t cipher {test_key(), false};

  auto wrong_version = vector_a;
  wrong_version[0] = 1;
  EXPECT_FALSE(stream::mic::open_packet(cipher, wrong_version));

  auto wrong_type = vector_a;
  wrong_type[1] = 0x62;
  EXPECT_FALSE(stream::mic::open_packet(cipher, wrong_type));
}

TEST(MicPacketTests, RejectsBadLengths) {
  crypto::cipher::gcm_t cipher {test_key(), false};

  for (std::size_t len = 0; len < vector_a.size(); ++len) {
    EXPECT_FALSE(stream::mic::open_packet(cipher, std::string_view {vector_a}.substr(0, len))) << "length " << len;
  }

  EXPECT_FALSE(stream::mic::open_packet(cipher, std::string(1401, '\x02')));
}

TEST(MicReplayWindowTests, AcceptsNewAndReorderedCounters) {
  stream::mic::replay_window_t window;
  EXPECT_TRUE(window.accept(10));
  EXPECT_TRUE(window.accept(12));
  EXPECT_TRUE(window.accept(11));  // late but inside the window
  EXPECT_TRUE(window.accept(100));
  EXPECT_TRUE(window.accept(100 - 63));  // oldest counter still in the window
}

TEST(MicReplayWindowTests, RejectsReplaysAndStaleCounters) {
  stream::mic::replay_window_t window;
  EXPECT_TRUE(window.accept(10));
  EXPECT_FALSE(window.accept(10));
  EXPECT_TRUE(window.accept(12));
  EXPECT_TRUE(window.accept(11));
  EXPECT_FALSE(window.accept(11));
  EXPECT_FALSE(window.accept(12));

  EXPECT_TRUE(window.accept(200));
  EXPECT_FALSE(window.accept(200 - 64));  // fell out of the window
  EXPECT_FALSE(window.accept(12));
}

TEST(MicReplayWindowTests, HandlesLargeJumps) {
  stream::mic::replay_window_t window;
  EXPECT_TRUE(window.accept(0));
  EXPECT_TRUE(window.accept(0xFFFFFFFF));
  EXPECT_FALSE(window.accept(0xFFFFFFFF));
  EXPECT_FALSE(window.accept(0));
}
