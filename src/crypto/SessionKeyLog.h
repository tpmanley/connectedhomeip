/*
 *
 *    Copyright (c) 2026 Project CHIP Authors
 *    All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

/**
 *    @file
 *      Debug-only export of message encryption keys, so that captured Matter
 *      traffic can be decrypted offline (e.g. by a packet analyzer).
 *
 *      Only available when built with `chip_enable_session_key_log = true`,
 *      which requires the raw session keystore. Exported keys are secret key
 *      material in the clear: never enable this in production builds.
 *
 *      Keys are read from the session key handles as raw bytes, so they are only
 *      meaningful when the application uses a raw-key SessionKeystore at runtime.
 *      With any other keystore implementation the exported bytes are an opaque
 *      handle, not a key.
 *
 *      Keys are exported for every session and fabric on the node, including
 *      sessions with other administrators' controllers.
 */

#pragma once

#include <crypto/CHIPCryptoPAL.h>
#include <crypto/CryptoBuildConfig.h>
#include <lib/core/NodeId.h>
#include <lib/support/Span.h>

#include <cstdint>

#if CHIP_CRYPTO_SESSION_KEY_LOG

namespace chip {
namespace Crypto {

using SessionKeySpan = FixedByteSpan<CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES>;

/**
 * Receives message encryption keys as the stack establishes them.
 *
 * Callbacks run on the Matter thread with the stack lock held. Implementations
 * must not retain the key spans past the call.
 */
class SessionKeyLogDelegate
{
public:
    virtual ~SessionKeyLogDelegate() = default;

    /**
     * Called twice for each activated CASE session, once per direction.
     *
     * @param sessionId     Session ID carried in the header of messages encrypted with `key`.
     * @param sourceNodeId  Node ID of the sender of those messages, which is part of the
     *                      nonce but usually omitted from unicast headers.
     * @param key           AES-128-CCM message encryption key.
     */
    virtual void OnCaseSessionKey(uint16_t sessionId, NodeId sourceNodeId, SessionKeySpan key) = 0;

    /**
     * Called twice for each activated PASE session, once per direction.
     *
     * No node ID is reported: PASE messages always use the undefined node ID (0) in the nonce.
     *
     * @param sessionId     Session ID carried in the header of messages encrypted with `key`.
     * @param key           AES-128-CCM message encryption key.
     */
    virtual void OnPaseSessionKey(uint16_t sessionId, SessionKeySpan key) = 0;

    /**
     * Called for each epoch key of a group key set that was successfully stored.
     *
     * Only epoch keys stored while a delegate is set are reported: key sets are persisted
     * as derived operational keys, so earlier epoch keys cannot be recovered later.
     */
    virtual void OnGroupEpochKey(FixedByteSpan<kCompressedFabricIdentifierSize> compressedFabricId, SessionKeySpan epochKey) = 0;
};

/**
 * Set the delegate that receives exported keys, or nullptr to stop exporting.
 * The delegate must outlive its registration.
 */
void SetSessionKeyLogDelegate(SessionKeyLogDelegate * delegate);

/** The current delegate, or nullptr when none is set. */
SessionKeyLogDelegate * GetSessionKeyLogDelegate();

/** Report a group epoch key to the current delegate, if any. Ignores spans of the wrong size. */
void ReportGroupEpochKey(ByteSpan compressedFabricId, ByteSpan epochKey);

} // namespace Crypto
} // namespace chip

#endif // CHIP_CRYPTO_SESSION_KEY_LOG
