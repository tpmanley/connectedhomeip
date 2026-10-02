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

#include <pw_unit_test/framework.h>

#include <SessionKeyLogFile.h>
#include <lib/core/StringBuilderAdapters.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

using namespace chip;

namespace {

constexpr uint8_t kKey[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
constexpr uint8_t kCompressedFabricId[] = { 0x87, 0xe1, 0xb0, 0x04, 0xe2, 0x35, 0xa1, 0x30 };

class TestSessionKeyLogFile : public ::testing::Test
{
protected:
    void SetUp() override
    {
        int fd = mkstemp(mPath);
        ASSERT_GE(fd, 0);
        close(fd);
    }

    void TearDown() override { unlink(mPath); }

    std::string ReadLog() const
    {
        std::ifstream file(mPath);
        std::stringstream contents;
        contents << file.rdbuf();
        return contents.str();
    }

    char mPath[32] = "/tmp/session_key_log_XXXXXX";
};

TEST_F(TestSessionKeyLogFile, WritesEachKeyLineType)
{
    SessionKeyLogFile log;
    ASSERT_EQ(log.Open(mPath), CHIP_NO_ERROR);
    log.OnPaseSessionKey(0x0c03, Crypto::SessionKeySpan(kKey));
    log.OnCaseSessionKey(0x1a2b, 0x0123456789abcdef, Crypto::SessionKeySpan(kKey));
    log.OnGroupEpochKey(FixedByteSpan<Crypto::kCompressedFabricIdentifierSize>(kCompressedFabricId), Crypto::SessionKeySpan(kKey));
    log.Close();

    EXPECT_EQ(ReadLog(),
              "PASE_KEY 0x0c03 00112233445566778899aabbccddeeff\n"
              "CASE_KEY 0x1a2b 0x0123456789abcdef 00112233445566778899aabbccddeeff\n"
              "GROUP_EPOCH_KEY 87e1b004e235a130 00112233445566778899aabbccddeeff\n");
}

TEST_F(TestSessionKeyLogFile, AppendsToExistingLog)
{
    {
        SessionKeyLogFile log;
        ASSERT_EQ(log.Open(mPath), CHIP_NO_ERROR);
        log.OnCaseSessionKey(0x0001, 0x1, Crypto::SessionKeySpan(kKey));
    }
    {
        SessionKeyLogFile log;
        ASSERT_EQ(log.Open(mPath), CHIP_NO_ERROR);
        log.OnCaseSessionKey(0x0002, 0x2, Crypto::SessionKeySpan(kKey));
    }

    EXPECT_EQ(ReadLog(),
              "CASE_KEY 0x0001 0x0000000000000001 00112233445566778899aabbccddeeff\n"
              "CASE_KEY 0x0002 0x0000000000000002 00112233445566778899aabbccddeeff\n");
}

TEST_F(TestSessionKeyLogFile, OpenFailsForUnwritablePath)
{
    SessionKeyLogFile log;
    EXPECT_EQ(log.Open("/nonexistent-dir/session_keys.log"), CHIP_ERROR_OPEN_FAILED);

    // Writes after a failed open are dropped rather than crashing.
    log.OnCaseSessionKey(0x0001, 0x1, Crypto::SessionKeySpan(kKey));
}

TEST_F(TestSessionKeyLogFile, CreatesFileReadableByOwnerOnly)
{
    unlink(mPath);

    SessionKeyLogFile log;
    ASSERT_EQ(log.Open(mPath), CHIP_NO_ERROR);
    log.Close();

    struct stat info;
    ASSERT_EQ(stat(mPath, &info), 0);
    EXPECT_EQ(info.st_mode & 0777, static_cast<mode_t>(0600));
}

TEST_F(TestSessionKeyLogFile, RefusesFileAccessibleByOthers)
{
    ASSERT_EQ(chmod(mPath, 0644), 0);

    SessionKeyLogFile log;
    EXPECT_EQ(log.Open(mPath), CHIP_ERROR_OPEN_FAILED);
    log.OnCaseSessionKey(0x0001, 0x1, Crypto::SessionKeySpan(kKey));
    EXPECT_EQ(ReadLog(), "");
}

TEST_F(TestSessionKeyLogFile, RefusesSymlink)
{
    std::string linkPath = std::string(mPath) + ".link";
    ASSERT_EQ(symlink(mPath, linkPath.c_str()), 0);

    SessionKeyLogFile log;
    EXPECT_EQ(log.Open(linkPath.c_str()), CHIP_ERROR_OPEN_FAILED);
    log.OnCaseSessionKey(0x0001, 0x1, Crypto::SessionKeySpan(kKey));
    EXPECT_EQ(ReadLog(), "");

    unlink(linkPath.c_str());
}

TEST_F(TestSessionKeyLogFile, RefusesNonRegularFile)
{
    SessionKeyLogFile log;
    EXPECT_EQ(log.Open("/dev/null"), CHIP_ERROR_OPEN_FAILED);
}

} // namespace
