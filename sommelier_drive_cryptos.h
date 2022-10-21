#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


typedef struct CSharedKeyCT {
  char *ptr;
} CSharedKeyCT;

typedef struct CFilePathCT {
  char *ptr;
} CFilePathCT;

typedef struct CPermissionCT {
  struct CSharedKeyCT shared_key_ct;
  struct CFilePathCT filepath_ct;
} CPermissionCT;

typedef struct CRecoveredSharedKey {
  char *shared_key;
  char *shared_key_hash;
} CRecoveredSharedKey;

typedef struct CFileCT {
  unsigned int num_cts;
  struct CSharedKeyCT *shared_key_cts;
  struct CFilePathCT *filepath_cts;
  char *shared_key_hash;
  char *contents_ct;
} CFileCT;

struct CPermissionCT addPermission(char *pk,
                                   struct CRecoveredSharedKey recovered_shared_key,
                                   char *filepath);

char *decryptContentsCT(struct CRecoveredSharedKey shared_key, char *ct);

char *decryptFilepath(char *sk, struct CFilePathCT ct);

struct CFilePathCT encryptFilepath(char *pk, char *filepath);

struct CFileCT encryptNewFile(char **pks,
                              unsigned int num_pk,
                              char *filepath,
                              uint8_t *contents_bytes,
                              unsigned int contents_bytes_size);

char *pkeGenPublicKey(char *sk);

char *pkeGenSecretKey(void);

char *pkeGenSignature(char *sk,
                      char *region_name,
                      char *method,
                      char *uri,
                      char **fields,
                      char **vals,
                      unsigned int num_field);

struct CRecoveredSharedKey recoverSharedKey(char *sk, struct CSharedKeyCT ct);

int verifySignature(char *pk,
                    char *region_name,
                    char *method,
                    char *uri,
                    char **fields,
                    char **vals,
                    unsigned int num_field,
                    char *signature);
