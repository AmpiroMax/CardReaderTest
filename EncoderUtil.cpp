#include "DataEncoder.h"
#include "des.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

void log(const CString &msg)
{
    printf("%S \n", msg);
}

int main(int argc, char *argv[])
{
    int errorCode = 0;
    DataEncoder encoder;
    CString inFileName("");
    CString outFileName("");
    CString iniFileName("FileEncoderDLL.ini");
    if (argc < 2)
    {
        log("Not enough params were passed! Expected at least 2");
        return -1;
    }

    inFileName = CString(argv[1]);
    outFileName = inFileName;

    if (argc == 3)
        outFileName = CString(argv[2]);

    if (argc == 4)
        iniFileName = CString(argv[3]);

    encoder.initialize(iniFileName, errorCode);
    encoder.encodeFile(inFileName, outFileName, errorCode);

    return 0;
}
