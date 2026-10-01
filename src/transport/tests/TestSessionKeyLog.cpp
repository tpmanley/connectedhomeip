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

#include <crypto/DefaultSessionKeystore.h>
#include <crypto/SessionKeyLog.h>
#include <lib/core/StringBuilderAdapters.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/Span.h>
#include <transport/CryptoContext.h>
#include <transport/SecureSessionTable.h>

#include <cstring>

using namespace chip;
using namespace chip::Crypto;

namespace {

constexpr uint16_t kInitiatorSessionId = 0x1111;
constexpr uint16_t kResponderSessionId = 0x2222;
constexpr NodeId kInitiatorNodeId      = 0x0000'0000'0000'0001;
constexpr NodeId kResponderNodeId      = 0x0000'0000'0000'0002;

constexpr uint8_t kSharedSecret[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                      0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                      0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

struct UnicastKeyRecord
{
    bool isPase;
    uint16_t sessionId;
    NodeId sourceNodeId; // kUndefinedNodeId for PASE, which reports no node ID.
    Symmetric128BitsKeyByteArray key;
};

class UnicastKeyRecorder : public SessionKeyLogDelegate
{
public:
    void OnCaseSessionKey(uint16_t sessionId, NodeId sourceNodeId, SessionKeySpan key) override
    {
        Record(false, sessionId, sourceNodeId, key);
    }

    void OnPaseSessionKey(uint16_t sessionId, SessionKeySpan key) override { Record(true, sessionId, kUndefinedNodeId, key); }

    void OnGroupEpochKey(FixedByteSpan<kCompressedFabricIdentifierSize> compressedFabricId, SessionKeySpan epochKey) override {}

    static constexpr size_t kMaxRecords = 2;
    UnicastKeyRecord mRecords[kMaxRecords];
    size_t mCount = 0;

private:
    void Record(bool isPase, uint16_t sessionId, NodeId sourceNodeId, SessionKeySpan key)
    {
        ASSERT_LT(mCount, kMaxRecords);
        UnicastKeyRecord & record = mRecords[mCount++];
        record.isPase             = isPase;
        record.sessionId          = sessionId;
        record.sourceNodeId       = sourceNodeId;
        memcpy(record.key, key.data(), key.size());
    }
};

class TestSessionKeyLog : public ::testing::Test
{
protected:
    void TearDown() override { SetSessionKeyLogDelegate(nullptr); }

    void InitContexts()
    {
        ASSERT_EQ(mInitiator.InitFromSecret(mKeystore, ByteSpan(kSharedSecret), ByteSpan(),
                                            CryptoContext::SessionInfoType::kSessionEstablishment,
                                            CryptoContext::SessionRole::kInitiator),
                  CHIP_NO_ERROR);
        ASSERT_EQ(mResponder.InitFromSecret(mKeystore, ByteSpan(kSharedSecret), ByteSpan(),
                                            CryptoContext::SessionInfoType::kSessionEstablishment,
                                            CryptoContext::SessionRole::kResponder),
                  CHIP_NO_ERROR);
    }

    DefaultSessionKeystore mKeystore;
    CryptoContext mInitiator;
    CryptoContext mResponder;
};

TEST_F(TestSessionKeyLog, ReportsEachDirectionAgainstReceiverSessionIdAndSender)
{
    InitContexts();

    UnicastKeyRecorder initiatorLog;
    SetSessionKeyLogDelegate(&initiatorLog);
    mInitiator.ReportCaseKeysToSessionKeyLog(kInitiatorSessionId, kResponderSessionId, kInitiatorNodeId, kResponderNodeId);

    UnicastKeyRecorder responderLog;
    SetSessionKeyLogDelegate(&responderLog);
    mResponder.ReportCaseKeysToSessionKeyLog(kResponderSessionId, kInitiatorSessionId, kResponderNodeId, kInitiatorNodeId);

    ASSERT_EQ(initiatorLog.mCount, 2u);
    ASSERT_EQ(responderLog.mCount, 2u);

    // Initiator-to-responder messages carry the responder's session ID and are sent by the initiator.
    const UnicastKeyRecord & i2rFromInitiator = initiatorLog.mRecords[0];
    const UnicastKeyRecord & i2rFromResponder = responderLog.mRecords[1];
    EXPECT_EQ(i2rFromInitiator.sessionId, kResponderSessionId);
    EXPECT_EQ(i2rFromInitiator.sourceNodeId, kInitiatorNodeId);
    EXPECT_EQ(i2rFromResponder.sessionId, kResponderSessionId);
    EXPECT_EQ(i2rFromResponder.sourceNodeId, kInitiatorNodeId);
    EXPECT_EQ(memcmp(i2rFromInitiator.key, i2rFromResponder.key, sizeof(i2rFromInitiator.key)), 0);

    // Responder-to-initiator messages carry the initiator's session ID and are sent by the responder.
    const UnicastKeyRecord & r2iFromInitiator = initiatorLog.mRecords[1];
    const UnicastKeyRecord & r2iFromResponder = responderLog.mRecords[0];
    EXPECT_EQ(r2iFromInitiator.sessionId, kInitiatorSessionId);
    EXPECT_EQ(r2iFromInitiator.sourceNodeId, kResponderNodeId);
    EXPECT_EQ(r2iFromResponder.sessionId, kInitiatorSessionId);
    EXPECT_EQ(r2iFromResponder.sourceNodeId, kResponderNodeId);
    EXPECT_EQ(memcmp(r2iFromInitiator.key, r2iFromResponder.key, sizeof(r2iFromInitiator.key)), 0);

    EXPECT_NE(memcmp(i2rFromInitiator.key, r2iFromInitiator.key, sizeof(i2rFromInitiator.key)), 0);
}

TEST_F(TestSessionKeyLog, ReportsPaseKeysWithoutNodeIds)
{
    InitContexts();

    UnicastKeyRecorder caseLog;
    SetSessionKeyLogDelegate(&caseLog);
    mInitiator.ReportCaseKeysToSessionKeyLog(kInitiatorSessionId, kResponderSessionId, kInitiatorNodeId, kResponderNodeId);

    UnicastKeyRecorder paseLog;
    SetSessionKeyLogDelegate(&paseLog);
    mInitiator.ReportPaseKeysToSessionKeyLog(kInitiatorSessionId, kResponderSessionId);

    // The same keys and session IDs are reported, through the PASE callback, which carries no node ID.
    ASSERT_EQ(paseLog.mCount, 2u);
    for (size_t i = 0; i < 2; i++)
    {
        EXPECT_TRUE(paseLog.mRecords[i].isPase);
        EXPECT_EQ(paseLog.mRecords[i].sessionId, caseLog.mRecords[i].sessionId);
        EXPECT_EQ(memcmp(paseLog.mRecords[i].key, caseLog.mRecords[i].key, sizeof(paseLog.mRecords[i].key)), 0);
    }
    EXPECT_EQ(paseLog.mRecords[0].sessionId, kResponderSessionId);
    EXPECT_EQ(paseLog.mRecords[1].sessionId, kInitiatorSessionId);
}

TEST_F(TestSessionKeyLog, ReportedKeyDecryptsMessage)
{
    InitContexts();

    UnicastKeyRecorder log;
    SetSessionKeyLogDelegate(&log);
    mInitiator.ReportCaseKeysToSessionKeyLog(kInitiatorSessionId, kResponderSessionId, kInitiatorNodeId, kResponderNodeId);
    ASSERT_EQ(log.mCount, 2u);
    const UnicastKeyRecord & outbound = log.mRecords[0];

    const uint8_t plainText[] = { 0x86, 0x74, 0x64, 0xe5, 0x0b, 0xd4, 0x0d, 0x90, 0xe1, 0x17, 0xa3, 0x2d, 0x4b, 0xd4, 0xe1, 0xe6 };
    uint8_t cipherText[sizeof(plainText)];
    PacketHeader header;
    header.SetSessionId(outbound.sessionId);
    MessageAuthenticationCode mac;
    CryptoContext::NonceStorage nonce;
    ASSERT_EQ(CryptoContext::BuildNonce(nonce, header.GetSecurityFlags(), header.GetMessageCounter(), outbound.sourceNodeId),
              CHIP_NO_ERROR);
    ASSERT_EQ(mInitiator.Encrypt(plainText, sizeof(plainText), cipherText, nonce, header, mac), CHIP_NO_ERROR);

    // Decrypt independently of the CryptoContext, the way an offline analyzer would: the AAD is the encoded header.
    uint8_t aad[64]; // Larger than any encoded packet header.
    uint16_t aadLength = 0;
    ASSERT_EQ(header.Encode(aad, sizeof(aad), &aadLength), CHIP_NO_ERROR);

    Aes128KeyHandle keyHandle;
    ASSERT_EQ(mKeystore.CreateKey(outbound.key, keyHandle), CHIP_NO_ERROR);
    uint8_t decrypted[sizeof(plainText)];
    EXPECT_EQ(AES_CCM_decrypt(cipherText, sizeof(cipherText), aad, aadLength, mac.GetTag(), header.MICTagLength(), keyHandle,
                              nonce.data(), nonce.size(), decrypted),
              CHIP_NO_ERROR);
    mKeystore.DestroyKey(keyHandle);
    EXPECT_EQ(memcmp(decrypted, plainText, sizeof(plainText)), 0);
}

TEST_F(TestSessionKeyLog, ReportsNothingWithoutKeys)
{
    UnicastKeyRecorder log;
    SetSessionKeyLogDelegate(&log);
    mInitiator.ReportCaseKeysToSessionKeyLog(kInitiatorSessionId, kResponderSessionId, kInitiatorNodeId, kResponderNodeId);
    EXPECT_EQ(log.mCount, 0u);
}

TEST_F(TestSessionKeyLog, ReportsNothingWithoutDelegate)
{
    InitContexts();

    UnicastKeyRecorder log;
    SetSessionKeyLogDelegate(&log);
    SetSessionKeyLogDelegate(nullptr);
    mInitiator.ReportCaseKeysToSessionKeyLog(kInitiatorSessionId, kResponderSessionId, kInitiatorNodeId, kResponderNodeId);
    EXPECT_EQ(log.mCount, 0u);
}

class TestSessionKeyLogActivation : public ::testing::Test
{
public:
    static void SetUpTestSuite() { ASSERT_EQ(Platform::MemoryInit(), CHIP_NO_ERROR); }
    static void TearDownTestSuite() { Platform::MemoryShutdown(); }

protected:
    void SetUp() override { mTable.Init(); }
    void TearDown() override { SetSessionKeyLogDelegate(nullptr); }

    // Creates a session with keys and activates it as the initiator, as PairingSession does.
    void ActivateSession(Transport::SecureSession::Type type, const ScopedNodeId & localNode, const ScopedNodeId & peerNode)
    {
        auto handle = mTable.CreateNewSecureSession(type, ScopedNodeId());
        ASSERT_TRUE(handle.HasValue());
        Transport::SecureSession * session = handle.Value()->AsSecureSession();
        ASSERT_EQ(session->GetCryptoContext().InitFromSecret(mKeystore, ByteSpan(kSharedSecret), ByteSpan(),
                                                             CryptoContext::SessionInfoType::kSessionEstablishment,
                                                             CryptoContext::SessionRole::kInitiator),
                  CHIP_NO_ERROR);
        mLocalSessionId = session->GetLocalSessionId();
        session->Activate(localNode, peerNode, CATValues(), kResponderSessionId, SessionParameters());
        session->MarkForEviction();
    }

    DefaultSessionKeystore mKeystore;
    Transport::SecureSessionTable mTable;
    uint16_t mLocalSessionId = 0;
};

TEST_F(TestSessionKeyLogActivation, CaseSessionReportsNodeIds)
{
    constexpr FabricIndex kFabricIndex = 1;
    UnicastKeyRecorder log;
    SetSessionKeyLogDelegate(&log);

    ActivateSession(Transport::SecureSession::Type::kCASE, ScopedNodeId(kInitiatorNodeId, kFabricIndex),
                    ScopedNodeId(kResponderNodeId, kFabricIndex));

    ASSERT_EQ(log.mCount, 2u);
    EXPECT_FALSE(log.mRecords[0].isPase);
    EXPECT_EQ(log.mRecords[0].sessionId, kResponderSessionId);
    EXPECT_EQ(log.mRecords[0].sourceNodeId, kInitiatorNodeId);
    EXPECT_FALSE(log.mRecords[1].isPase);
    EXPECT_EQ(log.mRecords[1].sessionId, mLocalSessionId);
    EXPECT_EQ(log.mRecords[1].sourceNodeId, kResponderNodeId);
}

TEST_F(TestSessionKeyLogActivation, PaseSessionReportsPaseKeys)
{
    // PASE messages use the undefined node ID in the nonce, whatever node IDs the session holds (e.g. a
    // commissioner's temporary local node ID), so PASE keys are reported without node IDs.
    constexpr NodeId kCommissionerTemporaryNodeId = 0xFFFF'FFFB'0000'0000;
    UnicastKeyRecorder log;
    SetSessionKeyLogDelegate(&log);

    ActivateSession(Transport::SecureSession::Type::kPASE, ScopedNodeId(kCommissionerTemporaryNodeId, kUndefinedFabricIndex),
                    ScopedNodeId());

    ASSERT_EQ(log.mCount, 2u);
    EXPECT_TRUE(log.mRecords[0].isPase);
    EXPECT_EQ(log.mRecords[0].sessionId, kResponderSessionId);
    EXPECT_TRUE(log.mRecords[1].isPase);
    EXPECT_EQ(log.mRecords[1].sessionId, mLocalSessionId);
}

} // namespace
