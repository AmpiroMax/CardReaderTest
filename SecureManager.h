#pragma once

#define _CRT_SECURE_NO_DEPRECATE

#include <atlstr.h>
#include <iostream>
#include <stdio.h>
#include <vector>
#include <winscard.h>

const int KEY_LENGTH = 24;

class SecureManager
{
 public:
    CString logger;
    CString emptyString;

    // private:
    SCARDCONTEXT hSC;

    CString fieldsDelimetr;
    CString dataDelimetr;
    CString encKeyFieldName;
    CString encDataTagName;
    CString readerName;

    int isInEncMode;
    int lineNumToRead;
    CString encKey;
    CString cipherKey;
    std::vector<std::pair<CString, int>> tagLenMap;

 public:
    SecureManager();

    // Initializing
    void initialize(const CString &iniFileName, const CString &formatFileName, int &codeError);

    CString manageData(const CString &data);

    // private:
    // Reading initial information from files
    CString getFormatString(const CString &filename, int &codeError);

    void readIniFile(const CString &iniFileName, int &codeError);

    CString setEncKeyFromFormatString(const CString &formatString, int &codeError);

    std::vector<std::pair<CString, int>> getTagLenFromFormatString(const CString &format);

    // Interaction with card
    std::vector<CString> getReadersNames(int &codeError);

    CString attemptToGetCardKey(int &codeError);

    CString getCardKey(int &codeError);

    // Encription
    CString encString(const CString &data, BYTE *key);

    CString decString(const CString &data, BYTE *key);

    // Processing tagged strings

    CString getEncyptedDataFromXMLString(const CString &xmlData);

    CString setDataToXMLString(const CString &xmlData, const CString &newData);

    CString coverWithTag(const CString &data, const CString &tag);

    CString makeXmlString(const CString &data);

    // Additional Functionality
    void printByteArray(const BYTE array[], int len);

    void log(const CString &msg);

    CString getLog();
};
