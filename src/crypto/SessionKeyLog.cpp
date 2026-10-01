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

#include <crypto/SessionKeyLog.h>

#include <lib/support/CodeUtils.h>
#include <lib/support/logging/CHIPLogging.h>

#if !CHIP_CRYPTO_KEYSTORE_RAW
#error "Session key log requires the raw session keystore"
#endif

namespace chip {
namespace Crypto {
namespace {

SessionKeyLogDelegate * gSessionKeyLogDelegate = nullptr;

} // namespace

void SetSessionKeyLogDelegate(SessionKeyLogDelegate * delegate)
{
    if (delegate != nullptr)
    {
        ChipLogError(SecureChannel, "Session key log enabled: message encryption keys will be exported in the clear");
    }
    gSessionKeyLogDelegate = delegate;
}

SessionKeyLogDelegate * GetSessionKeyLogDelegate()
{
    return gSessionKeyLogDelegate;
}

void ReportGroupEpochKey(ByteSpan compressedFabricId, ByteSpan epochKey)
{
    VerifyOrReturn(gSessionKeyLogDelegate != nullptr);
    VerifyOrReturn(compressedFabricId.size() == kCompressedFabricIdentifierSize);
    VerifyOrReturn(epochKey.size() == CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES);

    gSessionKeyLogDelegate->OnGroupEpochKey(FixedByteSpan<kCompressedFabricIdentifierSize>(compressedFabricId.data()),
                                            SessionKeySpan(epochKey.data()));
}

} // namespace Crypto
} // namespace chip
