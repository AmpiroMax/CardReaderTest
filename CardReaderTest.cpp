#include "DataEncoder.h"
#include "SecureManager.h"
#include "des.h"
#include <fstream>
#include <sstream>
#include <string>

SecureManager sm;
DataEncoder encoder;

void testInitFromFile(int &errorCode)
{
    sm.initialize("\\DeviceDLL.ini", "test_SS28KF20_200_enc.inp.txt", errorCode);
}

void testCardReading(int &errorCode)
{
    std::vector<CString> names = sm.getReadersNames(errorCode);
    CString activationKey("1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f");

    if (names.size() > 0)
    {
        printf("Card name: %S \n", names[0]);

        CString recievedCardKey = sm.attemptToGetCardKey(errorCode);
        printf("Recieved card key: %S \n", recievedCardKey);
    }
    else
    {
        printf("No card was found");
    }
}

void testHexBinConvertion(int &errorCode)
{
    BYTE byte_input[32];
    char orig_input[32];

    CString str("FAFAFAFA");

    CT2A ascii(str);
    char *workingCharPtr = ascii.m_psz;

    int byte_len = hex2bin((unsigned char *)workingCharPtr, byte_input);
    bin2hex(byte_input, orig_input, byte_len);

    printf("CString:       %S \n", str.GetString());
    printf("Const char:    %s \n", workingCharPtr);
    printf("bDATA: ");
    sm.printByteArray(byte_input, byte_len);
    printf("hDATA: %s \n", orig_input);
}

void test3DES(int &errorCode)
{
    BYTE key[] = {0x00, 0xA4, 0x04, 0x04, 0x10, 0xFF, 0x45, 0x43, 0x50, 0x52, 0x55, 0x55,
                  0x53, 0x4B, 0x45, 0x59, 0x42, 0x4F, 0x58, 0x00, 0x00, 0x11, 0x12, 0x22};

    char input[] = {"FAFAFAFA"};
    int input_len = 16;
    BYTE bData[16];
    BYTE encrypted[16];
    BYTE decrypted[16];

    int bLen = hex2bin((unsigned char *)input, bData);

    three_des3CBC_encrypt(bData, encrypted, key, input_len, key);
    three_des3CBC_decrypt(encrypted, decrypted, key, input_len, key);

    sm.printByteArray(bData, input_len);
    sm.printByteArray(encrypted, input_len);
    sm.printByteArray(decrypted, input_len);
}

void testDecryption(int &errorCode)
{
    BYTE key[] = {0x00, 0xA4, 0x04, 0x04, 0x10, 0xFF, 0x45, 0x43, 0x50, 0x52, 0x55, 0x55,
                  0x53, 0x4B, 0x45, 0x59, 0x42, 0x4F, 0x58, 0x00, 0x00, 0x11, 0x12, 0x22};

    CString data = "ABCD1234FFDD22EEABCD1234FFDD22EEABCD1234FFDD22EEABCD1234FFDD22EEABCD1234FFDD22EE";
    CString encData(sm.encString(data, key));
    CString decData(sm.decString(encData, key));

    printf("Data:      %S \n", data);
    printf("Encrypted: %S \n", encData);
    printf("Decrypted: %S \n", decData);

    CString filename("test_SS28KF20_200_enc.inp.txt");
    CString formatString = sm.getFormatString(filename, errorCode);

    std::vector<std::pair<CString, int>> tagLenMap = sm.getTagLenFromFormatString(formatString);

    sm.tagLenMap = tagLenMap;

    CString tagged = sm.makeXmlString(decData);

    printf("Tagged: %S \n", tagged);
}

void testContiniousReadingFromCard(int &errorCode)
{
    CString recievedCardKey = sm.emptyString;

    Sleep(1000);
    int readingAttempts = 30;

    recievedCardKey = sm.getCardKey(errorCode);
    printf("Recieved card key: %S \n", recievedCardKey);
}

void encryptFile(int &errorCode)
{
    CString fileEncryptName("test_forEnc.txt");
    CString saveFile("encrypted.txt");

    CString recievedCardKey = sm.getCardKey(errorCode);
    printf("KEY: %S \n", recievedCardKey);

    CT2A ascii(recievedCardKey);
    char *cstrKey = ascii.m_psz;
    BYTE key[24];
    int bLen = hex2bin((unsigned char *)cstrKey, key);

    printf("bLen: %d\n", bLen);
    sm.printByteArray(key, bLen);

    std::ifstream fileToRead(fileEncryptName);
    std::ofstream fileToSave(saveFile);
    std::string rawLine;

    while (std::getline(fileToRead, rawLine))
    {
        CString csLine(rawLine.c_str());
        CString encryptedLine = sm.encString(csLine, key);
        CString decryptedLine = sm.decString(encryptedLine, key);

        printf("Line:    %S \n", csLine);
        printf("EncLine: %S \n", encryptedLine);
        printf("DecLine: %S \n", decryptedLine);

        CT2A asciiStr(encryptedLine);
        char *cstrEncLine = asciiStr.m_psz;

        fileToSave << cstrEncLine << "\n";
        // fprintf(fileToSave, "%S", encryptedLine);
    }

    fileToRead.close();
    fileToSave.close();
}

void testDataByTag(int &errorCode)
{

    BYTE key[] = {0x00, 0xA4, 0x04, 0x04, 0x10, 0xFF, 0x45, 0x43, 0x50, 0x52, 0x55, 0x55,
                  0x53, 0x4B, 0x45, 0x59, 0x42, 0x4F, 0x58, 0x00, 0x00, 0x11, 0x12, 0x22};

    CString filename("test_SS28KF20_200_enc.inp.txt");
    CString formatString = sm.getFormatString(filename, errorCode);
    std::vector<std::pair<CString, int>> tagLenMap = sm.getTagLenFromFormatString(formatString);

    CString data("<TAG1>Hello</"
                 "TAG1><ENCRYPTED>ABCD1234FFDD22EEABCD1234FFDD22EEABCD1234FFDD22EEABCD1234FFDD22EEABCD1234FFDD22EE</"
                 "ENCRYPTED><TAG2>World</TAG2>");
    CString dataToEncode = sm.getEncyptedDataFromXMLString(data);
    CString encData(sm.encString(dataToEncode, key));
    CString decData(sm.decString(encData, key));

    sm.tagLenMap = tagLenMap;

    CString tagged = sm.makeXmlString(decData);
    CString processedData = sm.setDataToXMLString(data, tagged);

    printf("data:          %S\n", data);
    printf("dataToEncode:  %S\n", dataToEncode);
    printf("tagged:        %S\n", tagged);
    printf("processedData: %S", processedData);
}

void testEncoderInitilize(int &errorCode)
{
    CString iniFileName("FileEncoderDLL.ini");
    encoder.initialize(iniFileName, errorCode);
}

void testDataEncoding(int &errorCode)
{
    encoder.encodeFile(errorCode);
}

/*
TODO:
- test multiple card reading processes

*/

int main()
{
    sm.lineNumToRead = 1;

    int errorCode = 0;

    // testInitFromFile(errorCode);

    // testCardReading(errorCode);

    // testHexBinConvertion(errorCode);

    // test3DES(errorCode);

    // testDecryption(errorCode);

    // testContiniousReadingFromCard(errorCode);

    // encryptFile(errorCode);

    // testDataByTag(errorCode);

    testEncoderInitilize(errorCode);

    testDataEncoding(errorCode);

    printf("\n\n<---- Errors occured during test ----> \n\n%S \n\n%S", sm.getLog(), encoder.getLog());

    getchar();

    return 0;
}
