#pragma once

#define _CRT_SECURE_NO_DEPRECATE

#include "crc.h"
#include "des.h"

#include <atlstr.h>
#include <iostream>
#include <stdio.h>
#include <vector>
#include <winscard.h>

const int KEY_LENGTH = 26;

class SecureManager
{
 private:
    static SCARDCONTEXT hSC;

    static CString emptyString;
    static CString fieldsDelimetr;
    static CString dataDelimetr;
    static CString encKeyFieldName;

 public:
    SecureManager();
    // Reading initial information from files
    static CString getFormatString(const CString &filename, int lineNumToRead = 1);

    static CString getReaderNameFromIni(const CString &iniFileName);

    static CString getEncKeyFromFormatString(const CString &formatString);

    static std::vector<std::pair<CString, int>> getTagLenFromFormatString(const CString &format);

    // Interaction with card
    static std::vector<CString> getReadersNames();

    static CString getCardKey(const CString &readerName, const CString &activationKey);

    // Encription
    static CString encString(const CString &data, BYTE *key);

    static CString decString(const CString &data, BYTE *key);

    // Processing tagged strings

    static CString coverWithTag(const CString &data, const CString &tag);

    static CString makeXmlString(const CString &data, std::vector<std::pair<CString, int>> tagLenMap);

    // Additional Functionality
    static void printByteArray(const BYTE array[], int len);
};
