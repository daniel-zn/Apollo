/**
 * @file src/mic_packet.cpp
 * @brief Definitions for parsing client microphone packets.
 */
// standard includes
#include <cstring>

// lib includes
extern "C" {
#include <moonlight-common-c/src/Limelight-internal.h>
}

// local includes
#include "mic_packet.h"

namespace stream::mic {
  namespace {
    constexpr std::size_t header_size = 8;  // version, type, reserved (2), counter (4)
    constexpr std::size_t payload_header_size = 4;  // timestamp

    std::uint32_t load_le32(const char *data) {
      const auto *bytes = reinterpret_cast<const std::uint8_t *>(data);
      return std::uint32_t {bytes[0]} | std::uint32_t {bytes[1]} << 8 | std::uint32_t {bytes[2]} << 16 | std::uint32_t {bytes[3]} << 24;
    }
  }  // namespace

  std::optional<packet_t> open_packet(crypto::cipher::gcm_t &cipher, std::string_view packet) {
    if (packet.size() > MAX_MIC_PACKET_SIZE ||
        packet.size() <= header_size + MIC_GCM_TAG_LENGTH + payload_header_size) {
      return std::nullopt;
    }

    if (static_cast<std::uint8_t>(packet[0]) != MIC_PACKET_VERSION ||
        static_cast<std::uint8_t>(packet[1]) != MIC_PACKET_TYPE_OPUS) {
      return std::nullopt;
    }

    const auto counter = load_le32(packet.data() + 4);

    // Deterministic IV (NIST SP 800-38D 8.2.1): counter in the invocation field,
    // 'C' 'M' (client-originated microphone) in the fixed field.
    crypto::aes_t iv(12);
    std::memcpy(iv.data(), packet.data() + 4, sizeof(counter));
    iv[10] = 'C';
    iv[11] = 'M';

    std::vector<std::uint8_t> plaintext;
    if (cipher.decrypt(packet.substr(header_size), plaintext, &iv) != 0 ||
        plaintext.size() <= payload_header_size) {
      return std::nullopt;
    }

    packet_t result;
    result.counter = counter;
    result.timestamp = load_le32(reinterpret_cast<const char *>(plaintext.data()));
    result.opus.assign(plaintext.begin() + payload_header_size, plaintext.end());
    return result;
  }

  bool replay_window_t::accept(std::uint32_t counter) {
    if (!started) {
      started = true;
      highest = counter;
      seen = 1;
      return true;
    }

    if (counter > highest) {
      const auto shift = counter - highest;
      seen = shift >= WINDOW_SIZE ? 0 : seen << shift;
      seen |= 1;
      highest = counter;
      return true;
    }

    const auto age = highest - counter;
    if (age >= WINDOW_SIZE) {
      return false;
    }

    const auto bit = std::uint64_t {1} << age;
    if (seen & bit) {
      return false;
    }

    seen |= bit;
    return true;
  }
}  // namespace stream::mic
