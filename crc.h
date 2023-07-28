#ifndef CRC_H
#define CRCH

typedef unsigned char BYTE; // 8-bit byte

/**************************** DATA TYPES ****************************/
unsigned long UpdateCRC32(unsigned long crc, BYTE data);
unsigned long Calc_CRC32(BYTE *buff, int len);

#endif // CRC_H
