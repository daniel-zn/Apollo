# Remote Microphone Support

This branch lets a Moonlight client stream its microphone to an Apollo host on Windows. Games and chat
apps on the host hear the client's microphone as `Microphone (Steam Streaming Microphone)`.

## Overview

1. The client captures its default (or selected) microphone and encodes 20 ms mono Opus frames at 48 kHz.
2. It sends each frame to Apollo's microphone port as an AES-GCM authenticated packet.
3. Apollo authenticates and decodes the frames, then renders them into the playback endpoint
   `Speakers (Steam Streaming Microphone)`.
4. The Steam driver loops that endpoint into the recording endpoint `Microphone (Steam Streaming Microphone)`,
   which host applications select as their microphone.

## Requirements

- A client built from the `mic-passthrough` branch of
  [daniel-zn/moonlight-qt](https://github.com/daniel-zn/moonlight-qt), with **Stream microphone to host** enabled.
- Steam installed on the host, so Apollo can install the Steam Streaming Microphone driver from it.
- `stream_mic = enabled` in Apollo (Audio/Video tab).
- In each host application, select `Microphone (Steam Streaming Microphone)` as the input device.

Stock Moonlight clients and stock Apollo hosts are unaffected; the microphone is only used when both ends
support this protocol version.

## Protocol

The host advertises `a=x-apollo-mic:2` in its RTSP DESCRIBE response. A client that wants the microphone sets
up `streamid=mic` and learns the UDP port from the SETUP response (the base port + 12, 48001 by default). If
the host doesn't advertise support or the SETUP fails, the stream continues without a microphone.

Each UDP packet is:

| Bytes | Field |
|-------|-------|
| 1 | version (2) |
| 1 | type (0x61, Opus) |
| 2 | reserved |
| 4 | packet counter, little-endian |
| 16 | AES-GCM tag |
| rest | AES-128-GCM ciphertext of a 4-byte little-endian timestamp (48 kHz samples) followed by one Opus frame |

The key is the session's remote input key (the same key the control stream uses). The 12-byte IV is the
counter in bytes 0-3, zeros, then `'C' 'M'` in bytes 10-11. This is the same deterministic construction the
control (`'C' 'C'`) and video (`'V'`) streams use, so IVs never collide between streams. The client never
reuses a counter, so it stops sending after 2^32 packets (about 2.7 years at 50 packets per second).

The canonical definition is next to `MIC_SDP_ATTRIBUTE` in `third-party/moonlight-common-c/src/Limelight-internal.h`.

## Host behavior

- **Authentication:** packets that fail GCM authentication are dropped. The packet counter feeds a 64-packet
  replay window, so duplicated or replayed packets are dropped too.
- **One client at a time:** only one session drives the host microphone. A newly started session takes it over,
  which covers clients that reconnect before their old session times out. When the owning session ends, the
  next session that sends audio claims it. Switching streams clears the jitter buffer and resets the decoder.
- **Lifetime:** the Steam microphone device opens when the first microphone session starts and closes when the
  last one ends. Opening, closing, and writing are serialized, so a packet can't reach a device being torn down.
- **Disabled endpoints:** Steam (or the Sound settings) often leaves `Speakers (Steam Streaming Microphone)`
  disabled while nothing is streaming, and a disabled endpoint can't be opened. Apollo enables it while the device
  is open and disables it again afterwards.
- **Device format:** the Steam driver doesn't convert between its playback and recording endpoints, so both
  must use the same format. While the device is open, Apollo sets both to `2ch, 32-bit, 48000 Hz` and restores
  the previous formats when it closes.
- **Driver install:** when `install_steam_audio_drivers` and `stream_mic` are both enabled, Apollo installs the
  Steam Streaming Microphone driver if it's missing. It saves the default playback and recording devices for
  every role before the install and puts them back afterwards.
- **Device loss:** if Windows invalidates the Steam microphone endpoint mid-stream (for example, the audio
  service restarts), rendering stops until the client reconnects.

## Key files

- `src/mic_packet.cpp`: packet authentication and the replay window.
- `src/stream.cpp`: microphone socket, session ownership, and routing.
- `src/audio.cpp`: device reference counting and debug state.
- `src/platform/windows/audio.cpp`: Steam driver install and device selection.
- `src/platform/windows/mic_write.cpp`: jitter buffer, Opus decode, and WASAPI rendering.
- `tests/unit/test_mic_packet.cpp`: reference vectors and replay-window tests.

## Debugging

The Troubleshooting page shows packet, decode, and render counters, the active device formats, detected
signal level, and recent microphone events. Packets from a client that isn't paired with the session show up
as authentication failures.
