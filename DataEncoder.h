#pragma once

#define _CRT_SECURE_NO_DEPRECATE

#include <atlstr.h>
#include <iostream>
#include <stdio.h>
#include <vector>
#include <winscard.h>

class DataEncoder
{
    enum TypeKey
    {
        Billet,
        Encrypt
    };
 public:
    DataEncoder();

    void initialize(const CString &iniFileName, int &codeError);

    void encodeFile(const CString &inFileName, const CString &outFileName, int &codeError);

    CString getLog();

 private:
    // ---------- Variabels ----------
    int isInited = 0;

    SCARDCONTEXT hSC = 0;

    int mix;
    int formatLineNumber;
    int dataLineNumber;
    CString dataColumnName;
    CString readerName;
    CString _encKey;
    CString _cardKey;

    CString suffix;

    char paddingSym = 'D';
    CString emptyString = "";
    CString prefixAlphabet = "0123456789ABCD";
    CString fieldsDelimetr = ",";
    CString dataDelimetr = "#";

    CString logger;

    // ---------- Functions ----------

    // Interaction with card
    std::vector<CString> getReadersNames(int &codeError);

    CString attemptToGetCardKey(TypeKey type, int &codeError);

    CString getCardKey(int &codeError);

    CString getEncKey(int &codeError);

    // Encryption
    CString encString(const CString &data);

    CString decString(const CString &data);

    CString getRandomPrefix();

    // File processing

    int getDataFieldColumnIdx(const CString &columnNames, int &codeError);

    CString getFieldFromColumn(const CString &data, const int &columnIdx, int &codeError);

    CString setFieldToColumn(const CString &data, const CString &field, const int &columnIdx, int &codeError);

    // Additional functionality
    void log(const CString &str);
};
