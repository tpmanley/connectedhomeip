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

#pragma once

#include <crypto/SessionKeyLog.h>
#include <lib/core/CHIPError.h>

#include <cstdio>

namespace chip {

/**
 * Writes exported session keys to a text file that a packet analyzer can use
 * to decrypt captured Matter traffic. See docs/guides/session_key_log.md for
 * the format.
 *
 * The file is opened for appending, so several processes (e.g. a controller
 * and a device) can share one file and keys from earlier runs are kept.
 *
 * The file is created with mode 0600. Open() refuses a path that is a symlink,
 * is not a regular file, is owned by another user, or is accessible by group or
 * others, so keys are never written where other users could read them.
 */
class SessionKeyLogFile : public Crypto::SessionKeyLogDelegate
{
public:
    SessionKeyLogFile() = default;
    ~SessionKeyLogFile() override { Close(); }

    SessionKeyLogFile(const SessionKeyLogFile &)             = delete;
    SessionKeyLogFile & operator=(const SessionKeyLogFile &) = delete;

    CHIP_ERROR Open(const char * path);
    void Close();

    void OnCaseSessionKey(uint16_t sessionId, NodeId sourceNodeId, Crypto::SessionKeySpan key) override;
    void OnPaseSessionKey(uint16_t sessionId, Crypto::SessionKeySpan key) override;
    void OnGroupEpochKey(FixedByteSpan<Crypto::kCompressedFabricIdentifierSize> compressedFabricId,
                         Crypto::SessionKeySpan epochKey) override;

private:
    void WriteLine(const char * line);

    FILE * mFile = nullptr;
};

} // namespace chip
