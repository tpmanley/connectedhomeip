/*
 *    Copyright (c) 2026 Project CHIP Authors
 *    Licensed under the Apache License, Version 2.0 (the "License");
 */

#include <crypto/MatterKeyLog.h>

#include <lib/support/CodeUtils.h>
#include <lib/support/logging/CHIPLogging.h>

#include <cstdio>
#include <cstdlib>
#include <mutex>

namespace chip {
namespace {

std::mutex gKeyLogMutex;

// Returns the key log path from $MATTER_KEYLOG, or nullptr when logging is off.
const char * KeyLogPath()
{
    static const char * sPath = std::getenv("MATTER_KEYLOG");
    return (sPath != nullptr && sPath[0] != '\0') ? sPath : nullptr;
}

void AppendHex(FILE * fp, const uint8_t * data, size_t len)
{
    for (size_t i = 0; i < len; i++)
        fprintf(fp, "%02x", data[i]);
}

// Append one "CASE_KEY <session_id> <source_node_id> <key>" line.
void WriteCaseKey(uint16_t sessionId, NodeId sourceNodeId, const uint8_t * key, size_t key_len)
{
    const char * path = KeyLogPath();
    if (path == nullptr)
        return;

    std::lock_guard<std::mutex> lock(gKeyLogMutex);
    FILE * fp = fopen(path, "a");
    VerifyOrReturn(fp != nullptr,
                   ChipLogError(SecureChannel, "MATTER_KEYLOG: cannot open %s", path));

    fprintf(fp, "CASE_KEY 0x%04x 0x%016llx ", sessionId, static_cast<unsigned long long>(sourceNodeId));
    AppendHex(fp, key, key_len);
    fprintf(fp, "\n");
    fclose(fp);
}

} // namespace

void MatterKeyLogCaseSession(uint16_t localSessionId, uint16_t peerSessionId, NodeId localNodeId, NodeId peerNodeId,
                             const Crypto::Aes128KeyHandle & encryptionKey, const Crypto::Aes128KeyHandle & decryptionKey)
{
    if (KeyLogPath() == nullptr)
        return;

    // Raw key bytes; only meaningful with the raw key session keystore.
    const auto & encBytes = encryptionKey.As<Crypto::Symmetric128BitsKeyByteArray>();
    const auto & decBytes = decryptionKey.As<Crypto::Symmetric128BitsKeyByteArray>();

    // Outbound messages (encrypted by this node) carry the peer's session ID;
    // their nonce source is this node.
    WriteCaseKey(peerSessionId, localNodeId, encBytes, sizeof(encBytes));
    // Inbound messages (encrypted by the peer) carry this node's session ID;
    // their nonce source is the peer.
    WriteCaseKey(localSessionId, peerNodeId, decBytes, sizeof(decBytes));
}

void MatterKeyLogGroupEpochKey(const ByteSpan & compressedFabricId, const ByteSpan & epochKey)
{
    const char * path = KeyLogPath();
    if (path == nullptr)
        return;
    VerifyOrReturn(compressedFabricId.size() == 8 && epochKey.size() == Crypto::CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES);

    std::lock_guard<std::mutex> lock(gKeyLogMutex);
    FILE * fp = fopen(path, "a");
    VerifyOrReturn(fp != nullptr,
                   ChipLogError(SecureChannel, "MATTER_KEYLOG: cannot open %s", path));
    fprintf(fp, "GROUP_EPOCH_KEY ");
    AppendHex(fp, compressedFabricId.data(), compressedFabricId.size());
    fprintf(fp, " ");
    AppendHex(fp, epochKey.data(), epochKey.size());
    fprintf(fp, "\n");
    fclose(fp);
}

} // namespace chip
