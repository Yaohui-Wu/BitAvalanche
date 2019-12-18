// Usage (encryption): BitAvalanche -C/c plaintext.file ciphertext.file password
// Usage (decryption): BitAvalanche -P/p ciphertext.file plaintext.file
// Compiled on MacOS, Linux and *BSD.
// Talk is SO EASY, show you my GOD.
// Simple is beautiful.

#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

unsigned char auc1BitTable[8] = {0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80}, auc7BitsTable[8] = {0xFe, 0xFd, 0xFb, 0xF7, 0xEf, 0xDf, 0xBf, 0x7f};

void Encrypt(char *argv[])
{
// Each value of 256 numbers of key table that you can set randomly,
// yet you can freely to change to key table of 65536 numbers that you can set randomly,
// you can also freely to change to key table of 4294967296 numbers that you can set randomly,
// even if to change to key table of 18446744073709551616 numberes is no problem, which is only limited by the memory of your machine. WOW!
    unsigned char aucKeyTable[256] = {
          0x28, 0xe4, 0x4E, 0x1F, 0x97, 0x9A, 0xfC, 0xd0, 0x3F, 0x00, 0xa5, 0xc5, 0x62, 0x5E, 0x2C, 0x90, 0x16, 0x71, 0x80, 0xf8, 0x40, 0x8E, 0x4D, 0x47, 0xeF, 0x42, 0x13, 0x7E, 0xe9, 0x3E, 0x02, 0x96,
          0xaD, 0x54, 0x75, 0xdA, 0x78, 0xd1, 0x43, 0x50, 0x06, 0xb2, 0x65, 0x04, 0xeD, 0xe5, 0x0D, 0x6B, 0x32, 0x9B, 0x58, 0xc7, 0xbF, 0x3A, 0x8C, 0x7F, 0x48, 0xa6, 0x0F, 0x30, 0xa0, 0x6F, 0x51, 0x64,
          0x0B, 0x14, 0x87, 0xa9, 0x68, 0xf3, 0x70, 0x1D, 0xf2, 0xf6, 0xdB, 0xfE, 0x24, 0xdF, 0x6E, 0x12, 0x33, 0x81, 0xaF, 0xa7, 0x2E, 0x6C, 0x72, 0x66, 0xb7, 0x0E, 0x73, 0x9E, 0x60, 0x88, 0x3B, 0x5D,
          0x2F, 0x76, 0x63, 0xd2, 0x25, 0xf0, 0x79, 0xb6, 0x69, 0xbD, 0xbA, 0x94, 0x49, 0xe3, 0xf4, 0x29, 0x5C, 0xb5, 0x4B, 0x36, 0xc2, 0x6A, 0xd8, 0x6D, 0xe8, 0x09, 0xf7, 0x84, 0x8B, 0x5F, 0x86, 0x1B,
          0x89, 0x10, 0xbC, 0x8F, 0x4F, 0xa8, 0x07, 0x1C, 0x8D, 0xfB, 0xdD, 0x17, 0xc9, 0x9F, 0xb0, 0xcB, 0x67, 0x1A, 0x05, 0x23, 0x3D, 0xb4, 0x0A, 0x99, 0xdC, 0xf1, 0xd3, 0x08, 0x34, 0xeA, 0xdE, 0x9D,
          0x46, 0x22, 0xe0, 0x82, 0xbB, 0x7A, 0xb9, 0x0C, 0x7C, 0x01, 0x35, 0xbE, 0x53, 0x27, 0x11, 0xd5, 0x83, 0xb3, 0xc3, 0x45, 0xaE, 0x52, 0xcA, 0xc0, 0x38, 0x8A, 0xaA, 0x55, 0xfD, 0xcF, 0x3C, 0x59,
          0xb1, 0xcD, 0x2D, 0x57, 0xc8, 0x95, 0xd7, 0xd4, 0xe2, 0xfA, 0xc1, 0xf9, 0x31, 0x5B, 0x56, 0xb8, 0xaC, 0x03, 0x19, 0xf5, 0x26, 0xc4, 0x85, 0x98, 0xeE, 0xd6, 0xaB, 0xe1, 0xe7, 0x93, 0x9C, 0xeC,
          0x39, 0xcC, 0xa3, 0x20, 0x2B, 0x2A, 0x37, 0x41, 0xa2, 0x61, 0xc6, 0x7B, 0xe6, 0xa4, 0xeB, 0xa1, 0xfF, 0x92, 0x7D, 0x1E, 0x4A, 0x4C, 0x91, 0x21, 0xd9, 0x44, 0x74, 0x15, 0x77, 0x18, 0x5A, 0xcE};

// any password length
    unsigned long ulPasswordLength = -1;

// get password length;
    while(argv[2][++ulPasswordLength]);

    struct stat statFileSize;

    stat(argv[0], &statFileSize);

// get the plaintext file size
    unsigned long ulFileSize = statFileSize.st_size;

//  allocate storage space
    unsigned char *pucPlaintext = (unsigned char*)malloc(ulFileSize), *pucCiphertext = (unsigned char*)malloc(8 * ulFileSize);

// open the plaintext file descriptor
    int iPlaintextOrCiphertextFD = open(argv[0], O_RDONLY, S_IRUSR | S_IWUSR);

// read data from the plaintext file
    read(iPlaintextOrCiphertextFD, pucPlaintext, ulFileSize);

    close(iPlaintextOrCiphertextFD);

// process the plaintext data
    for(unsigned long i = 0; i < ulFileSize; i += 256)
    {
// key table convert 8 * 32 = 256 bytes of data at a time in order to generate the random number of "JunTai" distribution
        for(unsigned long jt = 0; jt < 32; ++jt)
        {
            unsigned long *pulKeySwap1 = (unsigned long*)aucKeyTable, *pulKeySwap2 = (unsigned long*)aucKeyTable, ulKeyTemp, ulKeyIndex;

            ulKeyIndex = (unsigned char)(argv[2][jt % ulPasswordLength]) % 32;

            ulKeyTemp = pulKeySwap1[jt];

            pulKeySwap1[jt] = pulKeySwap2[ulKeyIndex];

            pulKeySwap2[ulKeyIndex] = ulKeyTemp;
        }

// process bit avalanche
        for(unsigned long j = 0; j < 256 && i + j < ulFileSize; ++j)
        {
            for(unsigned long k = 0; k < 8; ++k)
            {
               pucCiphertext[8 * i + 8 * j + k] = (pucPlaintext[i + j] & auc1BitTable[k]) | (aucKeyTable[j] & auc7BitsTable[k]);
            }
        }

// use key table's value to change the password
        for(unsigned long l = 0; l < ulPasswordLength; ++l)
        {
            argv[2][l] = aucKeyTable[(unsigned char)(argv[2][l])];
        }
    }

// open the ciphertext file descriptor
    iPlaintextOrCiphertextFD = open(argv[1], O_CREAT | O_WRONLY, S_IREAD | S_IWRITE);

// write data to the ciphertext file
    write(iPlaintextOrCiphertextFD, pucCiphertext, 8 * ulFileSize);

    close(iPlaintextOrCiphertextFD);

    free(pucCiphertext);

    free(pucPlaintext);
}

void Decrypt(char *argv[])
{
    struct stat statFileSize;

    stat(argv[0], &statFileSize);

// get the ciphertext file size
    unsigned long ulFileSize = statFileSize.st_size;

//  allocate storage space
    unsigned char *pucCiphertext = (unsigned char*)malloc(ulFileSize);

// open the ciphertext file descriptor
    int iCiphertextOrPlaintextFD = open(argv[0], O_RDONLY, S_IRUSR | S_IWUSR);

// read data from the ciphertext file
    read(iCiphertextOrPlaintextFD, pucCiphertext, ulFileSize);

    close(iCiphertextOrPlaintextFD);

    ulFileSize /= 8;

    unsigned char *pucPlaintext = (unsigned char*)malloc(ulFileSize);

// process the ciphertext data
    for(unsigned long i = 0; i < ulFileSize; ++i)
    {
        pucPlaintext[i] = (pucCiphertext[8 * i] & auc1BitTable[0]) | (pucCiphertext[8 * i + 1] & auc1BitTable[1]) | (pucCiphertext[8 * i + 2] & auc1BitTable[2]) |
                          (pucCiphertext[8 * i + 3] & auc1BitTable[3]) | (pucCiphertext[8 * i + 4] & auc1BitTable[4]) | (pucCiphertext[8 * i + 5] & auc1BitTable[5]) |
                          (pucCiphertext[8 * i + 6] & auc1BitTable[6]) | (pucCiphertext[8 * i + 7] & auc1BitTable[7]);
    }

// open the plaintext file descriptor
    iCiphertextOrPlaintextFD = open(argv[1], O_CREAT | O_WRONLY, S_IREAD | S_IWRITE);

// write data to the plaintext file
    write(iCiphertextOrPlaintextFD, pucPlaintext, ulFileSize);

    close(iCiphertextOrPlaintextFD);

    free(pucPlaintext);

    free(pucCiphertext);
}

int main(int argc, char *argv[])
{
    if(argv[1][0] == '-')
    {
        if(argv[1][1] == 'C' || argv[1][1] == 'c')
        {
            Encrypt(argv + 2);
        }
        else if(argv[1][1] == 'P' || argv[1][1] == 'p')
        {
            Decrypt(argv + 2);
        }
    }
}
