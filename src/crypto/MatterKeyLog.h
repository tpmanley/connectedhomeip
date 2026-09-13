/*
 *    Copyright (c) 2026 Project CHIP Authors
 *    Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 *    @file
 *      Optional session-key logging for offline packet analysis (e.g. Wireshark).
 *
 *      When the environment variable MATTER_KEYLOG names a writable path, the
 *      functions below append the session keys used for message encryption to
 *      that file, in the format read by the Wireshark Matter dissector:
 *
 *          CASE_KEY <session_id> <source_node_id> <key>
 *          GROUP_EPOCH_KEY <compressed_fabric_id> <epoch_key>
 *
 *      This exposes secret key material in the clear and is intended only for
 *      debugging with test credentials. It requires the raw key session
 *      keystore (the default); with an opaque keystore (e.g. PSA) the logged
 *      bytes are not the usable key. Logging is a no-op unless MATTER_KEYLOG is
 *      set.
 */

#pragma once

#include <crypto/CHIPCryptoPAL.h>
#include <lib/core/DataModelTypes.h>
#include <lib/core/NodeId.h>
#include <lib/support/Span.h>

namespace chip {

/**
 * Log both directional keys of a CASE/PASE session.
 *
 * A secured unicast message carries the receiver's local session ID, so each
 * key is logged against the session ID of the messages it decrypts: the local
 * node's encryption key (its own outbound messages, which carry the peer's
 * session ID) and its decryption key (inbound messages, which carry the local
 * session ID). The source node ID is the sender that uses each key.
 */
void MatterKeyLogCaseSession(uint16_t localSessionId, uint16_t peerSessionId, NodeId localNodeId, NodeId peerNodeId,
                             const Crypto::Aes128KeyHandle & encryptionKey, const Crypto::Aes128KeyHandle & decryptionKey);

/** Log a group operational epoch key together with its compressed fabric ID. */
void MatterKeyLogGroupEpochKey(const ByteSpan & compressedFabricId, const ByteSpan & epochKey);

} // namespace chip
