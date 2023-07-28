#include "DataEncoder.h"
#include "crc.h"
#include "des.h"
#include <time.h>

const int KEY_LENGTH = 24;
const int buffSize = 1000;

DataEncoder::DataEncoder() {}

void DataEncoder::initialize(const CString &iniFileName, int &codeError)
{
    isInited = 0;
    srand(time(NULL));
    CString sectionName("MAIN");

    CString iniFilePath("");
    GetCurrentDirectory(MAX_PATH, iniFilePath.GetBufferSetLength(MAX_PATH));
    iniFilePath.ReleaseBuffer();
    iniFilePath += "\\" + iniFileName;

    // Reading INT vars
    mix = GetPrivateProfileInt(sectionName, CString("mix"), 4, iniFilePath);
    formatLineNumber = GetPrivateProfileInt(sectionName, CString("formatLineNumber"), 2, iniFilePath) - 1;
    dataLineNumber = GetPrivateProfileInt(sectionName, CString("dataLineNumber"), 3, iniFilePath) - 1;

    // Reading STR vars
    GetPrivateProfileString(sectionName, CString("dataColumnName"), CString(""),
                            dataColumnName.GetBufferSetLength(MAX_PATH), MAX_PATH, iniFilePath);
    dataColumnName.ReleaseBuffer();

    GetPrivateProfileString(sectionName, CString("suffix"), CString("_x"), suffix.GetBufferSetLength(MAX_PATH),
                            MAX_PATH, iniFilePath);
    suffix.ReleaseBuffer();

    GetPrivateProfileString(sectionName, CString("readerName"), CString(""), readerName.GetBufferSetLength(MAX_PATH),
                            MAX_PATH, iniFilePath);
    readerName.ReleaseBuffer();

    // Checking whether requested reader is available
    int isNameInList = 0;
    std::vector<CString> readersNames = getReadersNames(codeError);

    if (codeError != 0)
    {
        log("DataEncoder::initialize | Can't get readers names \n");
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

    // Recieving key for data encryption
    encKey = getEncKey(codeError);
    cardKey = getCardKey(codeError);

    isInited = 1;
}

void DataEncoder::encodeFile(const CString &inFileName, const CString &outFileName, int &codeError)
{
    log("DataEncoder::encodeFile | Starting file encoding");
    if (!isInited)
    {
        codeError = -1;
        log("DataEncoder::encodeFile | Class object is not initialized");
        return;
    }

    int currLineNum = 0;
    char line[buffSize];

    CT2A asciiInFileName(inFileName);
    char *cpInFileName = asciiInFileName.m_psz;

    char full[_MAX_PATH];
    if (_fullpath(full, cpInFileName, _MAX_PATH) != NULL)
        log("DataEncoder::encodeFile | Full path is : [" + CString(full) + "]");

    FILE *inFile = fopen(full, "r");

    CString realOutFileName("");
    if (outFileName == inFileName)
        realOutFileName = inFileName.Mid(0, inFileName.GetLength() - 4) + suffix + CString(".txt");
    else
        realOutFileName = outFileName;

    CT2A asciiOutFileName(realOutFileName);
    char *cpOutFileName = asciiOutFileName.m_psz;
    FILE *outFile = fopen(cpOutFileName, "w");

    log("DataEncoder::encodeFile | Recieving data from [" + inFileName + "]");
    log("DataEncoder::encodeFile | Saving data to      [" + realOutFileName + "]");

    if (inFile == NULL)
    {
        log("DataEncoder::encodeFile | Input file was not found \n");
        codeError = -1;
        return;
    }

    char *strPtr = fgets(line, buffSize, inFile);
    if (strPtr == NULL)
    {
        log("DataEncoder::getFormatString | Can't read first line from file \n");
        codeError = -1;
        return;
    }

    int columnIdx = getDataFieldColumnIdx(CString(line), codeError);
    if (codeError != 0)
        return;
    // Writing first line to out file
    fprintf(outFile, "%S", CString(line));

    CString formatString = "";
    while (currLineNum < dataLineNumber)
    {
        char *strPtr = fgets(line, buffSize, inFile);
        currLineNum += 1;
        if (strPtr == NULL)
        {
            log("DataEncoder::getFormatString | Can't read from file \n");
            codeError = -1;
            return;
        }
        if (currLineNum == formatLineNumber)
        {
            formatString = CString(line);
        }
    }
    // Writing second line to out file
    CString encField("ENC=");

    // Suppose ENC field is the first one
    formatString = setFieldToColumn(formatString, encField + encKey, 0, codeError);
    if (codeError != 0)
        return;

    fprintf(outFile, "%S", formatString);

    // Encrypting and writing all other lines to out file
    while (fgets(line, buffSize, inFile) != NULL)
    {
        CString data(line);
        CString field = getFieldFromColumn(data, columnIdx, codeError);
        if (codeError != 0)
            return;

        field = getRandomPrefix() + field;
        int paddingSize = field.GetLength() - 16 * (field.GetLength() / 16);
        field = field + CString(paddingSym, paddingSize);

        CString encField = encString(field);

        CString newData = setFieldToColumn(data, encField, columnIdx, codeError);
        if (codeError != 0)
            return;

        fprintf(outFile, "%S", newData);
    }

    fclose(inFile);
    fclose(outFile);

    log("DataEncoder::encodeFile | File was successfully encoded");
}

CString DataEncoder::getLog()
{
    return logger;
}

std::vector<CString> DataEncoder::getReadersNames(int &codeError)
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
            log("DataEncoder::getReadersNames | Reader is not in groups \n");
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
                log("DataEncoder::getReadersNames | Failed SCardFreeMemory \n");
                codeError = -1;
            }
            break;

        default:
            log("DataEncoder::getReadersNames | Failed SCardListReaders \n");
            codeError = -1;
            break;
    }
    return readersNames;
}

CString DataEncoder::attemptToGetCardKey(int &codeError)
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
        log("DataEncoder::attemptToGetCardKey | Reader is not found \n");
        codeError = -1;
        return emptyString;
    }

    // If there is no card, exit with error
    if (SCardConnect(hSC, (LPCTSTR)readerName, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, &hCardHandle,
                     &dwActiveProtocol) != 0)
    {
        log("DataEncoder::attemptToGetCardKey | No card in the reader \n");
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
        log("DataEncoder::attemptToGetCardKey | No connection with the card or the reader during AID send \n");
        SCardDisconnect(hCardHandle, SCARD_SHARE_SHARED);
        codeError = -1;
        return emptyString;
    }

    // Check Status word, if not success, exit with error
    if ((pbRecv[0] != 0x90) || (pbRecv[1] != 0x00))
    {
        log("DataEncoder::attemptToGetCardKey | There is no applet on card \n");
        codeError = -1;
        return emptyString;
    }

    // Send Command Get Key to Card
    dwRecv = sizeof(pbRecv);
    if (SCardTransmit(hCardHandle, SCARD_PCI_T0, GET_KEY, sizeof(GET_KEY), NULL, pbRecv, &dwRecv) != 0)
    {
        log("DataEncoder::attemptToGetCardKey | No connection with the card or the reader during Key recive \n");
        SCardDisconnect(hCardHandle, SCARD_SHARE_SHARED);
        codeError = -1;
        return emptyString;
    }

    // Check Status word, if not success, exit with error
    if ((pbRecv[0] != 0x61) || (pbRecv[1] != 0x18))
    {
        log("DataEncoder::attemptToGetCardKey | Do not run the command GET KEY \n");
        SCardDisconnect(hCardHandle, SCARD_SHARE_SHARED);
        codeError = -1;
        return emptyString;
    }

    // Take the key from card
    dwRecv = sizeof(pbRecv);
    if (SCardTransmit(hCardHandle, SCARD_PCI_T0, GET_RESPONSE, sizeof(GET_RESPONSE), NULL, pbRecv, &dwRecv) != 0)
    {
        log("DataEncoder::attemptToGetCardKey | Failed to read key from the card \n");
        SCardDisconnect(hCardHandle, SCARD_SHARE_SHARED);
        codeError = -1;
        return emptyString;
    }

    // Check Status word, if not success, exit with error
    if ((pbRecv[24] != 0x90) || (pbRecv[25] != 0x00))
    {
        log("DataEncoder::attemptToGetCardKey | Invalid status word accured \n");
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

CString DataEncoder::getCardKey(int &codeError)
{
    log("DataEncoder::getCardKey | Recieving card key from [" + readerName + "]");
    // int readingAttempts = 30;
    // CString recievedCardKey = emptyString;

    // int cardReadingError = 0;

    // do
    //{
    //    cardReadingError = 0;
    //    recievedCardKey = attemptToGetCardKey(cardReadingError);
    //    readingAttempts -= 1;
    //} while (cardReadingError != 0 && readingAttempts > 0);

    // if (cardReadingError != 0)
    //    codeError = cardReadingError;
    log("DataEncoder::getCardKey | Key was recieved");
    return CString("1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f");
}

CString DataEncoder::getEncKey(int &codeError)
{
    CString prefix = "";

    for (int i = 0; i < 2 * KEY_LENGTH; ++i)
    {
        int randomSymbolIdx = rand() % prefixAlphabet.GetLength();
        prefix += prefixAlphabet[randomSymbolIdx];
    }

    return prefix;
}

CString DataEncoder::encString(const CString &data)
{
    BYTE key[24];
    CT2A asciiCardKey(cardKey);
    char *cstrKey = asciiCardKey.m_psz;
    hex2bin((unsigned char *)cstrKey, key);

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

CString DataEncoder::decString(const CString &data)
{
    BYTE key[24];
    CT2A asciiCardKey(cardKey);
    char *cstrKey = asciiCardKey.m_psz;
    hex2bin((unsigned char *)cstrKey, key);

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

CString DataEncoder::getRandomPrefix()
{
    CString prefix = "";

    for (int i = 0; i < 2 * mix; ++i)
    {
        int randomSymbolIdx = rand() % prefixAlphabet.GetLength();
        prefix += prefixAlphabet[randomSymbolIdx];
    }

    return prefix;
}

int DataEncoder::getDataFieldColumnIdx(const CString &columnNames, int &codeError)
{
    int columnBegPos = 0;
    int columnIdx = -1;
    CString strToken("");

    while (strToken != dataColumnName)
    {
        strToken = columnNames.Tokenize(fieldsDelimetr, columnBegPos);
        columnIdx += 1;
        if (strToken.IsEmpty())
        {
            log("DataEncoder::getDataFieldColumnIdx | No dataColumnName was found in first line");
            codeError = -1;
            return -1;
        }
    }

    return columnIdx;
}

CString DataEncoder::getFieldFromColumn(const CString &data, const int &columnIdx, int &codeError)
{
    int columnBegPos = 0;
    int currColumnIdx = -1;
    CString strToken("");

    while (currColumnIdx != columnIdx)
    {
        strToken = data.Tokenize(fieldsDelimetr, columnBegPos);
        currColumnIdx += 1;
        if (strToken.IsEmpty())
        {
            log("DataEncoder::getFieldFromColumn | Error while processing line [ " + data + "]");
            codeError = -1;
            return emptyString;
        }
    }
    return strToken;
}

CString DataEncoder::setFieldToColumn(const CString &data, const CString &field, const int &columnIdx, int &codeError)
{
    int searchPos = 0;
    int currColumnIdx = -1;
    CString strToken("");

    while (currColumnIdx != columnIdx - 1)
    {
        strToken = data.Tokenize(fieldsDelimetr, searchPos);
        currColumnIdx += 1;

        if (strToken.IsEmpty())
        {
            log("DataEncoder::setFieldToColumn | Error while set processing line [ " + data + "]");
            codeError = -1;
            return emptyString;
        }
    }

    CString newData = data.Mid(0, searchPos) + field + fieldsDelimetr;

    strToken = data.Tokenize(fieldsDelimetr, searchPos);
    newData += data.Mid(searchPos);

    return newData;
}

void DataEncoder::log(const CString &str)
{
    CString msg = str.Mid(str.Find(CString("|"), 0) + 2);
    printf("%S \n", msg);
    logger += str + "\n";
}
