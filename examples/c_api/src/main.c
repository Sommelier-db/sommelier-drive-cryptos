#include "sommelier_drive_cryptos.h"
#include <stdio.h>

int main()
{
    char *sk = pkeGenSecretKey();
    char *pk = pkeGenPublicKey(sk);
    char *filepath = "/alice/texts/lecture1.txt";
    CFilePathCT filepathCT = encryptFilepath(pk, filepath);
    char *decrypted = decryptFilepathCT(sk, filepathCT);
    printf("decrypted: %s\n", decrypted);
    free(filepathCT.ptr);
}