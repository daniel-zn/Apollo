/**
 * @file src/mic_packet.h
 * @brief Declarations for parsing client microphone packets.
 */
#pragma once

// standard includes
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

// local includes
#include "crypto.h"

namespace stream::mic {
  /**
   * @brief A decrypted, authenticated microphone packet.
   * The wire format is documented next to MIC_SDP_ATTRIBUTE in moonlight-common-c's Limelight-internal.h.
   */
  struct packet_t {
    std::uint32_t counter;  ///< Per-connection packet counter (also the GCM IV invocation field).
    std::uint32_t timestamp;  ///< Capture timestamp in 48 kHz samples.
    std::vector<std::uint8_t> opus;  ///< One Opus frame.
  };

  /**
   * @brief Authenticate and decrypt one microphone packet.
   * @param cipher AES-GCM cipher keyed with the session's remote input key.
   * @param packet The UDP datagram.
   * @return The packet, or `std::nullopt` if it is malformed or fails authentication.
   */
  std::optional<packet_t> open_packet(crypto::cipher::gcm_t &cipher, std::string_view packet);

  /**
   * @brief Sliding-window replay filter over packet counters, as in RFC 4303 section 3.4.3.
   * Only feed it counters from authenticated packets.
   */
  class replay_window_t {
  public:
    /**
     * @brief Record a counter.
     * @return `true` if the counter hasn't been seen and isn't too old, `false` for a replay.
     */
    bool accept(std::uint32_t counter);

    static constexpr std::uint32_t WINDOW_SIZE = 64;

  private:
    bool started {};
    std::uint32_t highest {};
    std::uint64_t seen {};  ///< Bit N set means counter (highest - N) has been received.
  };
}  // namespace stream::mic
