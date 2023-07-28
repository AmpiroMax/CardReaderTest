
#include "SecureManager.h"
#include "crc.h"
#include "des.h"

SecureManager::SecureManager()
{
    hSC = 0;

    emptyString = CString("");
    fieldsDelimetr = CString(",");
    dataDelimetr = CString("#");
    encKeyFieldName = CString("ENC");
    encDataTagName = CString("ENCRYPTED");
    readerName = SecureManager::emptyString;

    isInEncMode = 0;
    lineNumToRead = 2;

    encKey = emptyString;
    cipherKey = emptyString;

    tagLenMap = std::vector<std::pair<CString, int>>();
}

void SecureManager::initialize(const CString &iniFileName, const CString &formatFileName, int &codeError)
{

    readIniFile(iniFileName, codeError);
    CString formatString = getFormatString(formatFileName, codeError);

    if (codeError != 0)
    {
        log("SecureManager::initialize | Can't read format string \n");
        codeError = -1;
        return;
    }

    setEncKeyFromFormatString(formatString, codeError);

    if (codeError != 0)
    {
        return;
    }

    // if there no "enc" in format string
    // class can't be further initialized
    // and not needed in it
    if (encKey == emptyString)
    {
        isInEncMode = 0;
        codeError = 0;
        return;
    }

    isInEncMode = 1;
    tagLenMap = getTagLenFromFormatString(formatString);
    cipherKey = getCardKey(codeError);
}

CString SecureManager::manageData(const CString &data)
{
    if (!isInEncMode)
        return data;

    CT2A ascii(cipherKey);
    char *cstrKey = ascii.m_psz;
    BYTE key[24];
    int bLen = hex2bin((unsigned char *)cstrKey, key);

    CString rawData = getEncyptedDataFromXMLString(data);
    CString decData(decString(rawData, key));

    CString taggedData = makeXmlString(decData);
    CString processedData = setDataToXMLString(data, taggedData);

    return processedData;
}

// Reading initial information from files
CString SecureManager::getFormatString(const CString &filename, int &codeError)
{
    const int buffSize = 1000;

    int currLineNum = 0; // lines are counting from 0
    char line[buffSize];

    CT2A ascii(filename);
    char *charPtrFilename = ascii.m_psz;
    FILE *file = fopen(charPtrFilename, "r");

    if (file == NULL)
    {
        log("SecureManager::getFormatString | No such file \n");
        codeError = -1;
        return emptyString;
    }

    while (currLineNum <= lineNumToRead)
    {
        char *strPtr = fgets(line, buffSize, file);
        if (strPtr == NULL)
        {
            log("SecureManager::getFormatString | Can't read from file \n");
            codeError = -1;
            return emptyString;
        }
        currLineNum += 1;
    }

    fclose(file);
    CString dataFormat(line);

    return dataFormat;
}

void SecureManager::readIniFile(const CString &iniFileName, int &codeError)
{
    CString sectionName("MAIN");

    CString iniFilePath("");
    GetCurrentDirectory(MAX_PATH, iniFilePath.GetBufferSetLength(MAX_PATH));
    iniFilePath.ReleaseBuffer();
    iniFilePath += iniFileName;

    lineNumToRead = GetPrivateProfileInt(sectionName, CString("lineNumToRead"), 2, iniFilePath);
    if (lineNumToRead < 1)
    {
        log("SecureManager::readIniFile | Invalid value in lineNumToRead accured \n");
        codeError = -1;
        return;
    }
    lineNumToRead = lineNumToRead - 1; // Line num in .ini file is counting from 1
                                       // however we are counting from zero
                                       // thus subtracting 1

    GetPrivateProfileString(sectionName, CString("readerName"), CString(""), readerName.GetBufferSetLength(MAX_PATH),
                            MAX_PATH, iniFilePath);
    readerName.ReleaseBuffer();

    int isNameInList = 0;
    std::vector<CString> readersNames = getReadersNames(codeError);

    if (codeError != 0)
    {
        log("SecureManager::readIniFile | Can't get readers names \n");
        return;
    }

    for (int i = 0; i < readersNames.size(); ++i)
    {
        if (readerName == readersNames[i])
        {
            isNameInList = 1;
            break;
        }
    }

    if (readerName.IsEmpty() || !isNameInList)
        readerName = readersNames[0];
}

CString SecureManager::setEncKeyFromFormatString(const CString &format, int &codeError)
{
    int encFieldPos = format.Find(encKeyFieldName);

    // File do not contain enc field. It is
    // a normal behavior. No errors accured.
    if (encFieldPos == -1)
        return emptyString;

    CString strToken = format.Tokenize(fieldsDelimetr, encFieldPos);

    int keyPos = strToken.Find(CString("="));

    encKey = strToken.Mid(keyPos + 1);

    if (encKey.GetLength() != 24 * 2)
    {
        log("SecureManager::setEncKeyFromFormatString | Invalid activationKey size \n");
        codeError = -1;
    }

    return encKey;
}

std::vector<std::pair<CString, int>> SecureManager::getTagLenFromFormatString(const CString &format)
{
    std::vector<std::pair<CString, int>> localtagLenMap;

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

        // localtagLenMap.push_back(std::make_pair(fieldName, atoi(fieldLen)));
        localtagLenMap.push_back(std::make_pair(fieldName, _wtoi(fieldLen)));

        strToken = format.Tokenize(fieldsDelimetr, nTokenPos);
    }

    return localtagLenMap;
}

// Interaction with card
std::vector<CString> SecureManager::getReadersNames(int &codeError)
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
        case SCARD_E_NO_READERS_AVAILABLE:
            log("SecureManager::getReadersNames | Reader is not in groups \n");
            codeError = -1;
            break;

        case SCARD_S_SUCCESS:
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
            {
                log("SecureManager::getReadersNames | Failed SCardFreeMemory \n");
                codeError = -1;
            }
            break;

        default:
            log("SecureManager::getReadersNames | Failed SCardListReaders \n");
            codeError = -1;
            break;
    }
    return readersNames;
}

CString SecureManager::attemptToGetCardKey(int &codeError)
{
    SCARDHANDLE hCardHandle = 0;

    DWORD dwActiveProtocol;
    DWORD dwRecv;

    BYTE Challenge[24];

    CT2A ascii(encKey);
    char *charPtrData = ascii.m_psz;
    int bLen = hex2bin((unsigned char *)charPtrData, Challenge);

    BYTE pbRecv[258];

    int Ptr = 0;
    FILE *ftemp;

    // If Reader is not found, exit with error
    if (SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hSC) != 0)
    {
        log("SecureManager::attemptToGetCardKey | Reader is not found \n");
        codeError = -1;
        return emptyString;
    }

    // If there is no card, exit with error
    if (SCardConnect(hSC, (LPCTSTR)readerName, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, &hCardHandle,
                     &dwActiveProtocol) != 0)
    {
        log("SecureManager::attemptToGetCardKey | No card in the reader \n");
        codeError = -1;
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
        log("SecureManager::attemptToGetCardKey | No connection with the card or the reader during AID send \n");
        SCardDisconnect(hCardHandle, SCARD_SHARE_SHARED);
        codeError = -1;
        return emptyString;
    }

    // Check Status word, if not success, exit with error
    if ((pbRecv[0] != 0x90) || (pbRecv[1] != 0x00))
    {
        log("SecureManager::attemptToGetCardKey | There is no applet on card \n");
        codeError = -1;
        return emptyString;
    }

    // Send Command Get Key to Card
    dwRecv = sizeof(pbRecv);
    if (SCardTransmit(hCardHandle, SCARD_PCI_T0, GET_KEY, sizeof(GET_KEY), NULL, pbRecv, &dwRecv) != 0)
    {
        log("SecureManager::attemptToGetCardKey | No connection with the card or the reader during Key recive \n");
        SCardDisconnect(hCardHandle, SCARD_SHARE_SHARED);
        codeError = -1;
        return emptyString;
    }

    // Check Status word, if not success, exit with error
    if ((pbRecv[0] != 0x61) || (pbRecv[1] != 0x18))
    {
        log("SecureManager::attemptToGetCardKey | Do not run the command GET KEY \n");
        SCardDisconnect(hCardHandle, SCARD_SHARE_SHARED);
        codeError = -1;
        return emptyString;
    }

    // Take the key from card
    dwRecv = sizeof(pbRecv);
    if (SCardTransmit(hCardHandle, SCARD_PCI_T0, GET_RESPONSE, sizeof(GET_RESPONSE), NULL, pbRecv, &dwRecv) != 0)
    {
        log("SecureManager::attemptToGetCardKey | Failed to read key from the card \n");
        SCardDisconnect(hCardHandle, SCARD_SHARE_SHARED);
        codeError = -1;
        return emptyString;
    }

    // Check Status word, if not success, exit with error
    if ((pbRecv[24] != 0x90) || (pbRecv[25] != 0x00))
    {
        log("SecureManager::attemptToGetCardKey | Invalid status word accured \n");
        SCardDisconnect(hCardHandle, SCARD_SHARE_SHARED);
        codeError = -1;
        return emptyString;
    }

    // Reader Off
    SCardDisconnect(hCardHandle, SCARD_SHARE_SHARED);

    char hRecKey[2 * KEY_LENGTH + 1];
    bin2hex(pbRecv, hRecKey, KEY_LENGTH);

    return CString(hRecKey);
}

CString SecureManager::getCardKey(int &codeError)
{
    int readingAttempts = 30;
    CString recievedCardKey = emptyString;

    int cardReadingError = 0;

    do
    {
        cardReadingError = 0;
        recievedCardKey = attemptToGetCardKey(cardReadingError);
        readingAttempts -= 1;
    } while (cardReadingError != 0 && readingAttempts > 0);

    if (cardReadingError != 0)
        codeError = cardReadingError;

    return recievedCardKey;
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

CString SecureManager::getEncyptedDataFromXMLString(const CString &xmlData)
{
    CString data("");

    int dataBegin = -1;
    int tagBegin = xmlData.Find(encDataTagName);
    dataBegin = xmlData.Find(CString(">"), tagBegin) + 1;

    int dataEnd = xmlData.Find(CString("<"), dataBegin);

    data = xmlData.Mid(dataBegin, dataEnd - dataBegin);
    return data;
}

CString SecureManager::setDataToXMLString(const CString &xmlData, const CString &newData)
{
    CString data("");

    int tagBegin = xmlData.Find("<" + encDataTagName);
    int tmp = xmlData.Find("</" + encDataTagName);
    int tagEnd = xmlData.Find(CString(">"), tmp);

    data = xmlData.Mid(0, tagBegin) + newData + xmlData.Mid(tagEnd + 1);
    return data;
}

// Processing tagged strings
CString SecureManager::coverWithTag(const CString &data, const CString &tag)
{
    CString tagged = "<" + tag + ">";
    tagged += data;
    tagged += "</" + tag + ">";
    return tagged;
}

CString SecureManager::makeXmlString(const CString &data)
{
    CString xmlString = "";

    int currPos = 0;
    for (size_t i = 0; i < tagLenMap.size(); ++i)
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
        // printf("\%02hhx", (unsigned char)array[i]);
    }
    printf("\n");
}

void SecureManager::log(const CString &msg)
{
    logger += msg;
}

CString SecureManager::getLog()
{
    return logger;
}
