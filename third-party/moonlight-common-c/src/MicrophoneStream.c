#include "Limelight-internal.h"
#include "PlatformSockets.h"

#define MIC_IV_LEN 12
#define MIC_DEFAULT_FRAME_DURATION_SAMPLES 960

static SOCKET micSocket = INVALID_SOCKET;
static PPLT_CRYPTO_CONTEXT micEncryptionCtx = NULL;
static uint32_t micPacketCounter = 0;
static bool micCounterExhausted = false;
static uint32_t micTimestamp = 0;

#pragma pack(push, 1)
typedef struct _MIC_PACKET_HEADER {
    uint8_t version;
    uint8_t packetType;
    uint16_t reserved;
    uint32_t counter;
} MIC_PACKET_HEADER, *PMIC_PACKET_HEADER;

typedef struct _MIC_PAYLOAD_HEADER {
    uint32_t timestamp;
} MIC_PAYLOAD_HEADER, *PMIC_PAYLOAD_HEADER;
#pragma pack(pop)

#define MAX_MIC_OPUS_SIZE (MAX_MIC_PACKET_SIZE - (int)sizeof(MIC_PACKET_HEADER) - MIC_GCM_TAG_LENGTH - (int)sizeof(MIC_PAYLOAD_HEADER))

int initializeMicrophoneStream(void) {
    int err;

    if (micSocket != INVALID_SOCKET) {
        return 0;
    }

    micEncryptionCtx = PltCreateCryptoContext();
    if (micEncryptionCtx == NULL) {
        return -1;
    }

    micPacketCounter = 0;
    micCounterExhausted = false;
    micTimestamp = 0;

    micSocket = bindUdpSocket(RemoteAddr.ss_family, &LocalAddr, AddrLen, 0, SOCK_QOS_TYPE_AUDIO);
    if (micSocket == INVALID_SOCKET) {
        err = LastSocketFail();
        PltDestroyCryptoContext(micEncryptionCtx);
        micEncryptionCtx = NULL;
        return err;
    }

    return 0;
}

// The caller must stop sending before calling this
void destroyMicrophoneStream(void) {
    if (micSocket != INVALID_SOCKET) {
        closeSocket(micSocket);
        micSocket = INVALID_SOCKET;
    }

    if (micEncryptionCtx != NULL) {
        PltDestroyCryptoContext(micEncryptionCtx);
        micEncryptionCtx = NULL;
    }

    micPacketCounter = 0;
    micCounterExhausted = false;
    micTimestamp = 0;
}

// Must not be called concurrently from multiple threads
int LiSendMicrophoneOpusDataEx(const unsigned char* opusData, int opusLength, uint32_t frameDurationSamples) {
    LC_SOCKADDR saddr;
    PMIC_PACKET_HEADER header;
    MIC_PAYLOAD_HEADER payloadHeader;
    unsigned char plaintext[sizeof(MIC_PAYLOAD_HEADER) + MAX_MIC_OPUS_SIZE];
    unsigned char packet[MAX_MIC_PACKET_SIZE];
    unsigned char iv[MIC_IV_LEN] = { 0 };
    uint32_t counterLE;
    int plaintextLength;
    int ciphertextLength;
    int err;

    if (micSocket == INVALID_SOCKET || micEncryptionCtx == NULL || opusData == NULL || opusLength <= 0) {
        return -1;
    }

    if (opusLength > MAX_MIC_OPUS_SIZE) {
        Limelog("MIC: Input data too large (%d)\n", opusLength);
        return -1;
    }

    // Never reuse an IV under this connection's key
    if (micCounterExhausted) {
        return -1;
    }

    header = (PMIC_PACKET_HEADER)packet;
    header->version = MIC_PACKET_VERSION;
    header->packetType = MIC_PACKET_TYPE_OPUS;
    header->reserved = 0;
    header->counter = LE32(micPacketCounter);

    payloadHeader.timestamp = LE32(micTimestamp);
    memcpy(plaintext, &payloadHeader, sizeof(payloadHeader));
    memcpy(plaintext + sizeof(payloadHeader), opusData, opusLength);
    plaintextLength = (int)sizeof(payloadHeader) + opusLength;

    counterLE = LE32(micPacketCounter);
    memcpy(iv, &counterLE, sizeof(counterLE));
    iv[10] = 'C'; // Client originated
    iv[11] = 'M'; // Microphone stream

    ciphertextLength = plaintextLength;
    if (!PltEncryptMessage(micEncryptionCtx, ALGORITHM_AES_GCM, 0,
                           (unsigned char*)StreamConfig.remoteInputAesKey, sizeof(StreamConfig.remoteInputAesKey),
                           iv, sizeof(iv),
                           packet + sizeof(MIC_PACKET_HEADER), MIC_GCM_TAG_LENGTH,
                           plaintext, plaintextLength,
                           packet + sizeof(MIC_PACKET_HEADER) + MIC_GCM_TAG_LENGTH, &ciphertextLength)) {
        Limelog("MIC: Encryption failed\n");
        return -1;
    }

    if (micPacketCounter == UINT32_MAX) {
        micCounterExhausted = true;
    }
    else {
        micPacketCounter++;
    }
    micTimestamp += frameDurationSamples != 0 ? frameDurationSamples : MIC_DEFAULT_FRAME_DURATION_SAMPLES;

    memcpy(&saddr, &RemoteAddr, sizeof(saddr));
    SET_PORT(&saddr, MicPortNumber);

    err = sendto(micSocket, (const char*)packet,
                 (int)sizeof(MIC_PACKET_HEADER) + MIC_GCM_TAG_LENGTH + ciphertextLength,
                 0, (struct sockaddr*)&saddr, AddrLen);
    if (err < 0) {
        return LastSocketError();
    }

    return err;
}

bool LiIsMicrophoneStreamActive(void) {
    return micSocket != INVALID_SOCKET;
}
