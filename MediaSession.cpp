/*
 * Copyright 2016-2017 TATA ELXSI
 * Copyright 2016-2017 Metrological
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "MediaSession.h"
#include <assert.h>
#include <iostream>
#include <sstream>
#include <string>
#include <string.h>
#include <vector>
#include <sys/utsname.h>

#define NYI_KEYSYSTEM "keysystem-placeholder"

using namespace std;

namespace CDMi {

// Parse out the first PlayReady initialization header found in the concatenated
// block of headers in _initData_.
// If a PlayReady header is found, this function returns true and the header
// contents are stored in _output_.
// Otherwise, returns false and _output_ is not touched.
bool parsePlayreadyInitializationData(const std::string& initData, std::string* output)
{
    BufferReader input(reinterpret_cast<const uint8_t*>(initData.data()), initData.length());

    static const uint8_t playreadySystemId[] = {
      0x9A, 0x04, 0xF0, 0x79, 0x98, 0x40, 0x42, 0x86,
      0xAB, 0x92, 0xE6, 0x5B, 0xE0, 0x88, 0x5F, 0x95,
    };

    // one PSSH box consists of:
    // 4 byte size of the atom, inclusive.  (0 means the rest of the buffer.)
    // 4 byte atom type, "pssh".
    // (optional, if size == 1) 8 byte size of the atom, inclusive.
    // 1 byte version, value 0 or 1.  (skip if larger.)
    // 3 byte flags, value 0.  (ignored.)
    // 16 byte system id.
    // (optional, if version == 1) 4 byte key ID count. (K)
    // (optional, if version == 1) K * 16 byte key ID.
    // 4 byte size of PSSH data, exclusive. (N)
    // N byte PSSH data.
    while (!input.IsEOF()) {
        size_t startPosition = input.pos();

        // The atom size, used for skipping.
        uint64_t atomSize;

        if (!input.Read4Into8(&atomSize)) {
            return false;
        }

        std::vector<uint8_t> atomType;
        if (!input.ReadVec(&atomType, 4)) {
            return false;
        }

        if (atomSize == 1) {
            if (!input.Read8(&atomSize)) {
                return false;
            }
        } else if (atomSize == 0) {
            atomSize = input.size() - startPosition;
        }

        if (memcmp(&atomType[0], "pssh", 4)) {
            if (!input.SkipBytes(atomSize - (input.pos() - startPosition))) {
                return false;
            }
            continue;
        }

        uint8_t version;
        if (!input.Read1(&version)) {
            return false;
        }

        if (version > 1) {
            // unrecognized version - skip.
            if (!input.SkipBytes(atomSize - (input.pos() - startPosition))) {
                return false;
            }
            continue;
        }

        // flags
        if (!input.SkipBytes(3)) {
            return false;
        }

        // system id
        std::vector<uint8_t> systemId;
        if (!input.ReadVec(&systemId, sizeof(playreadySystemId))) {
            return false;
        }

        if (memcmp(&systemId[0], playreadySystemId, sizeof(playreadySystemId))) {
            // skip non-Playready PSSH boxes.
            if (!input.SkipBytes(atomSize - (input.pos() - startPosition))) {
                return false;
            }
            continue;
        }

        if (version == 1) {
            // v1 has additional fields for key IDs.  We can skip them.
            uint32_t numKeyIds;
            if (!input.Read4(&numKeyIds)) {
                return false;
            }

            if (!input.SkipBytes(numKeyIds * 16)) {
                return false;
            }
        }

        // size of PSSH data
        uint32_t dataLength;
        if (!input.Read4(&dataLength)) {
            return false;
        }

        output->clear();
        if (!input.ReadString(output, dataLength)) {
            return false;
        }

        return true;
    }

    // we did not find a matching record
    return false;
}

MediaKeySession::MediaKeySession(const uint8_t *f_pbInitData, uint32_t f_cbInitData, const uint8_t *f_pbCDMData, uint32_t f_cbCDMData, int32_t licenseType)
        : m_prdyHandle(nullptr)
        , m_oDecryptContext()
        , m_oDecryptContextKey()
        , m_DecryptBufferSize(100000)
        , m_DecryptBuffer(nullptr)
        , m_eKeyState(KEY_ERROR)
        , m_fCommit(false)
        , m_piCallback(nullptr)
        , m_customData(reinterpret_cast<const char*>(f_pbCDMData), f_cbCDMData)
        , m_licenseType(licenseType)
        , _decoderLock() {

    DRM_Prdy_Init_t settings;

    std::string initData(reinterpret_cast<const char *>(f_pbInitData), f_cbInitData);
    std::string playreadyInitData;

    m_oDecryptContext.pKeyContext = &m_oDecryptContextKey;

    DRM_Prdy_GetDefaultParamSettings(&settings);
    settings.hdsFileName = reinterpret_cast<char *>(::strdup("/tmp/wpe.hds"));

    if (m_licenseType == Temporary) {
        ::remove(settings.hdsFileName);
    }

    m_rgchSessionID = new char[SESSION_ID_SIZE + 1]();

    printf("Constructing PlayReady Session [%p]\n", this);

    if (generateSessionId()) {

        m_prdyHandle = DRM_Prdy_Initialize(&settings);
        if (m_prdyHandle != nullptr) {

            int rc = NEXUS_Memory_Allocate(m_DecryptBufferSize, nullptr, reinterpret_cast<void **>(&m_DecryptBuffer));
            if (rc == 0) {

                if (!parsePlayreadyInitializationData(initData, &playreadyInitData)) {
                    playreadyInitData = initData;
                }

                DRM_Prdy_Error_e dr = DRM_Prdy_fail;
                dr = DRM_Prdy_Content_SetProperty(
                        m_prdyHandle,
                        DRM_Prdy_contentSetProperty_eAutoDetectHeader,
                        reinterpret_cast<const uint8_t *>(playreadyInitData.data()),
                        playreadyInitData.size());

                if (dr == DRM_Prdy_ok) {
                    m_eKeyState = KEY_INIT;
                    printf("Playready Session Initialized \n");
                }
            }
        }
    }
}

MediaKeySession::~MediaKeySession(void)
{

    if (m_oDecryptContext.pDecrypt != nullptr)
        DRM_Prdy_Reader_Close(&m_oDecryptContext);

    if (m_prdyHandle != nullptr)
        DRM_Prdy_Uninitialize(m_prdyHandle);

    if (m_DecryptBuffer != nullptr)
        NEXUS_Memory_Free(m_DecryptBuffer);

    delete [] m_rgchSessionID;

    m_eKeyState = KEY_CLOSED;

    printf("Destructing PlayReady Session [%p]\n", this);
}

const char *MediaKeySession::GetSessionId(void) const
{

    return m_rgchSessionID;
}

const char *MediaKeySession::GetKeySystem(void) const
{

    return NYI_KEYSYSTEM; // FIXME : replace with keysystem and test.
}

void MediaKeySession::Run(const IMediaKeySessionCallback *f_piMediaKeySessionCallback)
{

    if (f_piMediaKeySessionCallback) {

        m_piCallback = const_cast<IMediaKeySessionCallback *>(f_piMediaKeySessionCallback);

        playreadyGenerateKeyRequest();
    } else {

        m_piCallback = nullptr;
    }
}

bool MediaKeySession::playreadyGenerateKeyRequest()
{

    DRM_Prdy_Error_e dr = DRM_Prdy_fail;
    unsigned int cbChallenge = 0;
    unsigned int cchSilentURL = 0;
    char *pbChallenge = nullptr;
    char *pchSilentURL = nullptr;

    // The current state MUST be KEY_INIT otherwise error out.
    if ((m_eKeyState != KEY_INIT) || (m_prdyHandle == nullptr)) {

        m_eKeyState = KEY_ERROR;

        printf("playreadyGenerateKeyRequest FAIL! \n");
        if (m_piCallback)
            m_piCallback->OnError(0, CDMi_S_FALSE, "KeyError");
        return false;
    }

    dr = DRM_Prdy_Reader_Bind(m_prdyHandle, &m_oDecryptContext);
    if (dr != DRM_Prdy_fail) {
        // Try to figure out the size of the license acquisition
        // challenge to be returned.
        dr = DRM_Prdy_Get_Buffer_Size(
                m_prdyHandle,
                DRM_Prdy_getBuffer_licenseAcq_challenge,
                m_customData.empty() ? nullptr : reinterpret_cast<const uint8_t *>(m_customData.c_str()),
                m_customData.length(),
                &cchSilentURL,
                &cbChallenge);

        if (dr == DRM_Prdy_ok) {

            if (cchSilentURL > 0) {

                pchSilentURL = reinterpret_cast<char *>(::malloc(cchSilentURL + 1));
                ::memset(pchSilentURL, 0, sizeof(cchSilentURL + 1));
            }

            // Allocate buffer that is sufficient to store the license acquisition
            // challenge.
            if (cbChallenge > 0) {

                pbChallenge = reinterpret_cast<char *>(::malloc(cbChallenge + 1));
                ::memset(pbChallenge, 0, sizeof(cbChallenge + 1));
            }

            dr = DRM_Prdy_LicenseAcq_GenerateChallenge(
                    m_prdyHandle,
                    m_customData.empty() ? nullptr : m_customData.c_str(),
                    m_customData.length(),
                    pchSilentURL,
                    &cchSilentURL,
                    pbChallenge,
                    &cbChallenge);

            bool challengeResult = false;
            if (dr == DRM_Prdy_ok) {

                m_eKeyState = KEY_PENDING;

                if (m_piCallback)
                    m_piCallback->OnKeyMessage((const uint8_t *) pbChallenge, cbChallenge, (char *) pchSilentURL);

                challengeResult = true;
            } else {

                m_eKeyState = KEY_ERROR;
                if (m_piCallback)
                    m_piCallback->OnError(0, CDMi_S_FALSE, "KeyError");
            }

            if (pbChallenge)
                free(pbChallenge);
            if (pchSilentURL)
                free(pchSilentURL);
            return challengeResult;
        }
    }

    m_eKeyState = KEY_ERROR;
    printf("playreadyGenerateKeyRequest FAIL! \n");
    if (m_piCallback)
        m_piCallback->OnError(0, CDMi_S_FALSE, "KeyError");

    return false;
}

CDMi_RESULT MediaKeySession::Load(void)
{

  return CDMi_S_FALSE;
}

void MediaKeySession::Update(const uint8_t *m_pbKeyMessageResponse, uint32_t  m_cbKeyMessageResponse)
{

    DRM_Prdy_License_Response_t oLicenseResponse = { DRM_Prdy_License_Protocol_Type_eUnknownProtocol, 0 };
    DRM_Prdy_DecryptSettings_t pDecryptSettings;

    // The current state MUST be KEY_PENDING otherwise error out.
    if ( (m_pbKeyMessageResponse != nullptr)
         && (m_cbKeyMessageResponse > 0)
         && (m_eKeyState == KEY_PENDING)
         && (DRM_Prdy_LicenseAcq_ProcessResponse(
                 m_prdyHandle,
                 reinterpret_cast<const char *>(m_pbKeyMessageResponse),
                 m_cbKeyMessageResponse,
                 &oLicenseResponse) == DRM_Prdy_ok) ) {

        if (!m_fCommit) {
            DRM_Prdy_Reader_Bind(m_prdyHandle, &m_oDecryptContext);
        }

        printf("playreadyProcessKey did everything\n");
        m_eKeyState = KEY_READY;

        if ((m_piCallback != nullptr) && (m_eKeyState == KEY_READY) && (oLicenseResponse.cAcks > 0)) {
            for (uint8_t i = 0; i < oLicenseResponse.cAcks; ++i) {
                if (oLicenseResponse.rgoAcks[i].dwResult >= 0) {
                    // Make MS endianness to Cenc endianness.
                    //ToggleKeyIdFormat(DRM_ID_SIZE, oLicenseResponse.m_rgoAcks[i].oKID.rgb);

                    m_piCallback->OnKeyStatusUpdate("KeyUsable",
                       reinterpret_cast<uint8_t*>(&(oLicenseResponse.rgoAcks[i].oKID)),
                       sizeof(DRM_Prdy_guid_t));
                }
            }
            m_piCallback->OnKeyStatusesUpdated();
            printf("Key processed, now ready for content decryption\n");
            return;
        }
    }
    printf("Playready failed processing license response\n");
    m_eKeyState = KEY_ERROR;

    if (m_piCallback != nullptr) {
        for (uint8_t i = 0; i < oLicenseResponse.cAcks; ++i) {
            if (oLicenseResponse.rgoAcks[i].dwResult >= 0) {
                m_piCallback->OnKeyStatusUpdate("KeyError",
                   reinterpret_cast<uint8_t*>(&(oLicenseResponse.rgoAcks[i].oKID)),
                   sizeof(DRM_Prdy_guid_t));
            }
        }
        m_piCallback->OnKeyStatusesUpdated();
    }

    return;
}

CDMi_RESULT MediaKeySession::Remove(void)
{
    DRM_Prdy_Cleanup_LicenseStores(m_prdyHandle);

    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::Close(void)
{

    return CDMi_S_FALSE;
}

CDMi_RESULT MediaKeySession::Decrypt(
        const uint8_t *f_pbSessionKey,
        uint32_t f_cbSessionKey,
        const uint32_t *f_pdwSubSampleMapping,
        uint32_t f_cdwSubSampleMapping,
        const uint8_t *f_pbIV,
        uint32_t f_cbIV,
        const uint8_t *payloadData,
        uint32_t payloadDataSize,
        uint32_t *f_pcbOpaqueClearContent,
        uint8_t **f_ppbOpaqueClearContent,
        const uint8_t /* keyIdLength */,
        const uint8_t* /* keyId */,
        bool /* initWithLast15 */)

{

    DRM_Prdy_Error_e dr = DRM_Prdy_fail;
    DRM_Prdy_AES_CTR_Info_t oAESContext;

    if (sizeof(oAESContext.qwInitializationVector) < f_cbIV) {

        printf("oAESContext.qwInitializationVector smaller than ivSize. %d %d \n", sizeof(oAESContext.qwInitializationVector), f_cbIV);
        return CDMi_S_FALSE;
    }

    const uint8_t* source = reinterpret_cast<const uint8_t*>(f_pbIV);
    uint8_t* destination = reinterpret_cast<uint8_t*>(&oAESContext.qwInitializationVector);

    for (uint32_t index = 0; index < (f_cbIV / 2); index++) {

        destination[index] = source[f_cbIV - index - 1];
        destination[f_cbIV - index - 1] = source[index];
    }

    oAESContext.qwBlockOffset = 0;
    oAESContext.bByteOffset = 0;

    if (payloadDataSize >  m_DecryptBufferSize) {

        uint8_t* newBuffer = nullptr;
        int rc = NEXUS_Memory_Allocate(payloadDataSize, nullptr, reinterpret_cast<void**>(&newBuffer));
        if( rc == 0 ) {

            ::memcpy(newBuffer, payloadData, payloadDataSize);

            _decoderLock.Lock();
            NEXUS_Memory_Free(m_DecryptBuffer);
            m_DecryptBuffer = newBuffer;
            m_DecryptBufferSize = payloadDataSize;
            _decoderLock.Unlock();

            printf("m_DecryptBufferSize to small, use larger buffer. newSize: %d \n", payloadDataSize);
        } else {

            printf("m_DecryptBufferSize to small, use larger buffer. could not allocate memory %d \n", payloadDataSize);
            return CDMi_S_FALSE;
        }
    }

    _decoderLock.Lock();
    memcpy(m_DecryptBuffer, payloadData, payloadDataSize);

    if ( DRM_Prdy_Reader_Decrypt(&m_oDecryptContext, &oAESContext, m_DecryptBuffer, payloadDataSize) == DRM_Prdy_ok ) {

        if ( (!m_fCommit) && ( DRM_Prdy_Reader_Commit(m_prdyHandle) == DRM_Prdy_ok ) )
            m_fCommit = true;

        // Return clear content.
        *f_pcbOpaqueClearContent = payloadDataSize;
        *f_ppbOpaqueClearContent = static_cast<uint8_t *>(m_DecryptBuffer);

        _decoderLock.Unlock();
        return CDMi_SUCCESS;
    }

    _decoderLock.Unlock();
    return CDMi_S_FALSE;
}

CDMi_RESULT MediaKeySession::ReleaseClearContent(
        const uint8_t *f_pbSessionKey,
        uint32_t f_cbSessionKey,
        const uint32_t  f_cbClearContentOpaque,
        uint8_t  *f_pbClearContentOpaque )
{

  return CDMi_SUCCESS;
}

bool MediaKeySession::generateSessionId()
{

    uint8_t sessionID[SESSION_ID_SIZE];
    uint32_t B64SessionIDSize = DRM_Prdy_Cch_Base64_Equiv( SESSION_ID_SIZE );
    uint16_t B64SessionID[B64SessionIDSize];
    DRM_Prdy_Error_e dr = DRM_Prdy_fail;

    // Take this pointer as session identifier
    ::memcpy(sessionID, reinterpret_cast<uint8_t*>(this), SESSION_ID_SIZE);

    if(B64SessionID != NULL) {

        // Base64 encoded version of session identifier
        dr = DRM_Prdy_B64_EncodeW(sessionID, SESSION_ID_SIZE, B64SessionID, &B64SessionIDSize);
        if (dr != DRM_Prdy_ok) {

            printf("DRM_Prdy_B64_EncodeW failed = 0x%x\n", dr);
            return false;
        }

        // Copy encoded session identifier as char*
        std::copy(B64SessionID, B64SessionID + (sizeof(char)*SESSION_ID_SIZE), m_rgchSessionID);

        printf("Session ID generated: %s\n", m_rgchSessionID);
        return true;
    }

    return false;
}

}  // namespace CDMi
