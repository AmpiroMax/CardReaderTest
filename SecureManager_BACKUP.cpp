#include "SecureManager.h"

SCARDCONTEXT SecureManager::hSC = 0;

CString SecureManager::emptyString = CString("");
CString SecureManager::fieldsDelimetr = CString(",");
CString SecureManager::dataDelimetr = CString("#");
CString SecureManager::encKeyFieldName = CString("ENC");

SecureManager::SecureManager() {}

// Reading initial information from files
CString SecureManager::getFormatString(const CString &filename, int lineNumToRead)
{
    const int buffSize = 1000;

    int currLineNum = 0; // lines are counting from 0
    char line[buffSize];

    CT2A ascii(filename);
    char *charPtrFilename = ascii.m_psz;
    FILE *file = fopen(charPtrFilename, "r");

    if (file == NULL)
    {
        printf("No such file \n");
        return CString("-1");
    }

    while (currLineNum <= lineNumToRead)
    {
        char *strPtr = fgets(line, buffSize, file);
        if (strPtr == NULL)
        {
            printf("Can't read line#%d from file \n", currLineNum);
            return CString("-1");
        }
        currLineNum += 1;
    }

    fclose(file);
    CString dataFormat(line);

    return dataFormat;
}

CString SecureManager::getReaderNameFromIni(const CString &iniFileName)
{
    CString sectionName("");
    CString keyName("");
    CString defaultValue("");

    CT2A ascii(iniFileName);
    const char *charPtrData = ascii.m_psz;

    // CString readerName = GetPrivateProfileString(sectionName, keyName, defaultValue, charPtrData);
    return keyName;
}

CString SecureManager::getEncKeyFromFormatString(const CString &format)
{
    int encFieldPos = format.Find(encKeyFieldName);
    if (encFieldPos == -1)
        return emptyString;

    CString strToken = format.Tokenize(fieldsDelimetr, encFieldPos);

    int keyPos = strToken.Find(dataDelimetr);

    return strToken.Mid(keyPos + 1);
}

std::vector<std::pair<CString, int>> SecureManager::getTagLenFromFormatString(const CString &format)
{
    std::vector<std::pair<CString, int>> tagLenMap;

    int nTokenPos = 0;
    CString strToken = format.Tokenize(fieldsDelimetr, nTokenPos);

    int encKeyIdx = strToken.Find(encKeyFieldName);
    if (encKeyIdx != -1)
        strToken = format.Tokenize(fieldsDelimetr, nTokenPos);

    while (!strToken.IsEmpty())
    {
        int dataLenDelimetrIDX = strToken.Find(dataDelimetr);
        CString fieldName = strToken.Mid(0, dataLenDelimetrIDX);
        CString fieldLen = strToken.Mid(dataLenDelimetrIDX + 1);

        tagLenMap.push_back({fieldName, _wtoi(fieldLen)});

        strToken = format.Tokenize(fieldsDelimetr, nTokenPos);
    }

    return tagLenMap;
}

// Interaction with card
std::vector<CString> SecureManager::getReadersNames()
{
    std::vector<CString> readersNames;
    LPTSTR pmszReaders = NULL;
    LPTSTR pReader;
    LONG lReturn, lReturn2;
    DWORD cch = SCARD_AUTOALLOCATE;

    // Retrieve the list the readers.
    // hSC was set by a previous call to SCardEstablishContext.
    lReturn = SCardListReaders(hSC, NULL, (LPTSTR)&pmszReaders, &cch);
    switch (lReturn)
    {
        case SCARD_E_NO_READERS_AVAILABLE: printf("Reader is not in groups.\n"); break;

        case SCARD_S_SUCCESS:
            // Do something with the multi string of readers.
            // Output the values.
            // A double-null terminates the list of values.
            pReader = pmszReaders;

            while ('\0' != *pReader)
            {
                readersNames.push_back(CString(pReader));
                // Advance to the next value.
                pReader = pReader + wcslen((wchar_t *)pReader) + 1;
            }
            // Free the memory.
            lReturn2 = SCardFreeMemory(hSC, pmszReaders);
            if (SCARD_S_SUCCESS != lReturn2)
                printf("Failed SCardFreeMemory\n");
            break;

        default: printf("Failed SCardListReaders\n"); break;
    }
    return readersNames;
}

CString SecureManager::getCardKey(const CString &readerName, const CString &activationKey)
{
    SCARDHANDLE hCardHandle = 0;

    DWORD dwActiveProtocol;
    DWORD dwRecv;

    BYTE Challenge[24];
    BYTE pbRecv[258];

    int Ptr = 0;
    FILE *ftemp;

    // If Reader is not found, exit with error
    if (SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hSC) != 0)
    {
        printf("Reader is not found \r\n");
        return emptyString;
    }

    // If there is no card, exit with error
    if (SCardConnect(hSC, (LPCTSTR)readerName, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, &hCardHandle,
                     &dwActiveProtocol) != 0)
    {
        printf("No card in the reader \r\n");
        return emptyString;
    }
    // Set APDU Select Applet ID
    static const BYTE SELECT_AID[] = {0x00, 0xA4, 0x04, 0x04, 0x10, 0xFF, 0x45, 0x43, 0x50, 0x52, 0x55,
                                      0x53, 0x4B, 0x45, 0x59, 0x42, 0x4F, 0x58, 0x00, 0x00, 0x11};
    // Set APDU Get Key
    BYTE GET_KEY[] = {0x80, 0x40, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    // Copy Challenge to APDU Get Key
    memcpy(GET_KEY + 5, Challenge, 24);

    // Set APDU Get Response for Key
    BYTE GET_RESPONSE[] = {0x00, 0xC0, 0x00, 0x00, 0x18};

    // Send Command Select AID to Card
    dwRecv = sizeof(pbRecv);
    if (SCardTransmit(hCardHandle, SCARD_PCI_T0, SELECT_AID, sizeof(SELECT_AID), NULL, pbRecv, &dwRecv) != 0)
    {
        printf("No connection with the card or the reader \r\n");
        SCardDisconnect(hCardHandle, SCARD_SHARE_SHARED);
        return emptyString;
    }

    // Check Status word, if not success, exit with error
    if ((pbRecv[0] != 0x90) || (pbRecv[1] != 0x00))
    {
        printf("There is no applet on card\r\n");
        return emptyString;
    }

    // Send Command Get Key to Card
    dwRecv = sizeof(pbRecv);
    if (SCardTransmit(hCardHandle, SCARD_PCI_T0, GET_KEY, sizeof(GET_KEY), NULL, pbRecv, &dwRecv) != 0)
    {
        printf("No connection with the card or the reader \r\n");
        SCardDisconnect(hCardHandle, SCARD_SHARE_SHARED);
        return emptyString;
    }

    // Check Status word, if not success, exit with error
    if ((pbRecv[0] != 0x61) || (pbRecv[1] != 0x18))
    {
        printf("Do not run the command GET KEY \r\n");
        SCardDisconnect(hCardHandle, SCARD_SHARE_SHARED);
        return emptyString;
    }

    // Take the key from card
    dwRecv = sizeof(pbRecv);
    if (SCardTransmit(hCardHandle, SCARD_PCI_T0, GET_RESPONSE, sizeof(GET_RESPONSE), NULL, pbRecv, &dwRecv) != 0)
    {
        printf("Failed to read key from the card \r\n");
        SCardDisconnect(hCardHandle, SCARD_SHARE_SHARED);
        return emptyString;
    }

    // Check Status word, if not success, exit with error
    if ((pbRecv[24] != 0x90) || (pbRecv[25] != 0x00))
    {
        printf("Failed to read key from the card \r\n");
        SCardDisconnect(hCardHandle, SCARD_SHARE_SHARED);
        return emptyString;
    }

    // Reader Off
    SCardDisconnect(hCardHandle, SCARD_SHARE_SHARED);

    char hRecKey[2 * KEY_LENGTH + 1];
    bin2hex(pbRecv, hRecKey, KEY_LENGTH);

    return CString(hRecKey);
}

// Encription
CString SecureManager::encString(const CString &data, BYTE *key)
// Encryptring hex string and returning hex string
//
// data: CString   - string in HEX form
// key: BYTE*      - key which used to encrypt data
// return: CString - encrypted data in HEX form string
{
    BYTE *bData = new BYTE[data.GetLength()];
    BYTE *bEncrypted = new BYTE[data.GetLength()];
    char *hEncrypted = new char[data.GetLength() + 1];

    CT2A ascii(data);
    char *charPtrData = ascii.m_psz;

    int bLen = hex2bin((unsigned char *)charPtrData, bData);
    three_des3CBC_encrypt(bData, bEncrypted, key, bLen, key);
    bin2hex(bEncrypted, hEncrypted, bLen);

    CString str(hEncrypted);

    delete[] bData;
    delete[] bEncrypted;
    delete[] hEncrypted;

    return str;
}

CString SecureManager::decString(const CString &data, BYTE *key)
// Decryptring hex string and returning hex string
//
// data: CString   - encrypted string in HEX form
// key: BYTE*      - key which used to decrypt data
// return: CString - decrypted data in HEX form string
{
    BYTE *bData = new BYTE[data.GetLength()];
    BYTE *bDecrypted = new BYTE[data.GetLength()];
    char *hDecrypted = new char[data.GetLength() + 1];

    CT2A ascii(data);
    char *charPtrData = ascii.m_psz;

    int bLen = hex2bin((unsigned char *)charPtrData, bData);

    three_des3CBC_decrypt(bData, bDecrypted, key, bLen, key);
    bin2hex(bDecrypted, hDecrypted, bLen);

    CString str(hDecrypted);

    delete[] bData;
    delete[] bDecrypted;
    delete[] hDecrypted;

    return str;
}

// Processing tagged strings
CString SecureManager::coverWithTag(const CString &data, const CString &tag)
{
    CString tagged = "<" + tag + ">";
    tagged += data;
    tagged += "</" + tag + ">";
    return tagged;
}

CString SecureManager::makeXmlString(const CString &data, std::vector<std::pair<CString, int>> tagLenMap)
{
    CString xmlString = "";

    int currPos = 0;
    for (int i = 0; i < tagLenMap.size(); ++i)
    {
        CString field = data.Mid(currPos, tagLenMap[i].second);
        xmlString += coverWithTag(field, tagLenMap[i].first);
        currPos += tagLenMap[i].second;
    }

    return xmlString;
}

// Additional Functionality
void SecureManager::printByteArray(const BYTE array[], int len)
{
    for (int i = 0; i < len; ++i)
    {
        printf("\%02hhx", (unsigned char)array[i]);
    }
    printf("\n");
}