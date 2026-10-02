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

#include "SessionKeyLogFile.h"

#include <crypto/CHIPCryptoPAL.h>
#include <lib/support/BytesToHex.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/StringBuilder.h>
#include <lib/support/logging/CHIPLogging.h>

#include <cerrno>
#include <cinttypes>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace chip {
namespace {

// Longest line: "GROUP_EPOCH_KEY " + 16 hex + " " + 32 hex + "\n".
constexpr size_t kMaxLineLength = 80;

template <size_t N>
void AddHex(StringBuilderBase & builder, FixedByteSpan<N> bytes)
{
    char hex[2 * N + 1];
    SuccessOrDie(Encoding::BytesToLowercaseHexString(bytes.data(), bytes.size(), hex, sizeof(hex)));
    builder.Add(hex);
    Crypto::ClearSecretData(reinterpret_cast<uint8_t *>(hex), sizeof(hex));
}

// Holds one log line, which contains key material, and wipes it when done.
class LineBuffer
{
public:
    ~LineBuffer() { Crypto::ClearSecretData(reinterpret_cast<uint8_t *>(mBuffer), sizeof(mBuffer)); }

    StringBuilderBase & Builder() { return mBuilder; }

private:
    char mBuffer[kMaxLineLength];
    StringBuilderBase mBuilder{ mBuffer, sizeof(mBuffer) };
};

} // namespace

CHIP_ERROR SessionKeyLogFile::Open(const char * path)
{
    Close();

    // Create the file readable by its owner only, and never follow a symlink, so keys cannot be
    // read by other users or redirected into a file someone else planted at the path.
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        ChipLogError(AppServer, "Cannot open session key log %s: %s", path, strerror(errno));
        return CHIP_ERROR_OPEN_FAILED;
    }

    // An existing file must be a regular file we own that nobody else can access.
    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != geteuid() || (info.st_mode & (S_IRWXG | S_IRWXO)) != 0)
    {
        ChipLogError(AppServer, "Refusing session key log %s: must be a regular file owned by this user with mode 0600", path);
        close(fd);
        return CHIP_ERROR_OPEN_FAILED;
    }

    mFile = fdopen(fd, "a");
    if (mFile == nullptr)
    {
        ChipLogError(AppServer, "Cannot open session key log %s: %s", path, strerror(errno));
        close(fd);
        return CHIP_ERROR_OPEN_FAILED;
    }
    // Keep key material out of stdio buffers; each line is written with a single call.
    setvbuf(mFile, nullptr, _IONBF, 0);
    return CHIP_NO_ERROR;
}

void SessionKeyLogFile::Close()
{
    if (mFile != nullptr)
    {
        fclose(mFile);
        mFile = nullptr;
    }
}

void SessionKeyLogFile::OnCaseSessionKey(uint16_t sessionId, NodeId sourceNodeId, Crypto::SessionKeySpan key)
{
    LineBuffer buffer;
    StringBuilderBase & line = buffer.Builder();
    line.AddFormat("CASE_KEY 0x%04x 0x%016" PRIx64 " ", sessionId, sourceNodeId);
    AddHex(line, key);
    line.Add("\n");
    WriteLine(line.c_str());
}

void SessionKeyLogFile::OnPaseSessionKey(uint16_t sessionId, Crypto::SessionKeySpan key)
{
    LineBuffer buffer;
    StringBuilderBase & line = buffer.Builder();
    line.AddFormat("PASE_KEY 0x%04x ", sessionId);
    AddHex(line, key);
    line.Add("\n");
    WriteLine(line.c_str());
}

void SessionKeyLogFile::OnGroupEpochKey(FixedByteSpan<Crypto::kCompressedFabricIdentifierSize> compressedFabricId,
                                        Crypto::SessionKeySpan epochKey)
{
    LineBuffer buffer;
    StringBuilderBase & line = buffer.Builder();
    line.Add("GROUP_EPOCH_KEY ");
    AddHex(line, compressedFabricId);
    line.Add(" ");
    AddHex(line, epochKey);
    line.Add("\n");
    WriteLine(line.c_str());
}

void SessionKeyLogFile::WriteLine(const char * line)
{
    VerifyOrReturn(mFile != nullptr);
    // One unbuffered write per line, so lines from processes sharing the file do not interleave.
    fputs(line, mFile);
}

} // namespace chip
