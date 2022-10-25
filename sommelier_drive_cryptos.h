#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


typedef struct CAuthorizationSeedCT {
  char *ptr;
} CAuthorizationSeedCT;

typedef struct CContentsBytes {
  const uint8_t *ptr;
  size_t len;
} CContentsBytes;

typedef struct CRecoveredSharedKey {
  char *shared_key;
  char *shared_key_hash;
} CRecoveredSharedKey;

typedef struct CFilePathCT {
  char *ptr;
} CFilePathCT;

typedef struct CSharedKeyCT {
  char *ptr;
} CSharedKeyCT;

typedef struct CFileCT {
  size_t num_cts;
  struct CSharedKeyCT *shared_key_cts;
  struct CFilePathCT *filepath_cts;
  char *shared_key_hash;
  char *contents_ct;
} CFileCT;

typedef struct CReadPermissionCT {
  struct CSharedKeyCT shared_key_ct;
  struct CFilePathCT filepath_ct;
} CReadPermissionCT;

char *computePermissionHash(unsigned int user_id, char *parent_filepath);

char *decryptAuthorizationSeedCT(char *sk, struct CAuthorizationSeedCT authorization_seed_ct);

struct CContentsBytes decryptContentsCT(struct CRecoveredSharedKey shared_key, char *ct);

char *decryptFilepathCT(char *sk, struct CFilePathCT ct);

struct CAuthorizationSeedCT encryptAuthorizationSeed(char *pk, char *authorization_seed);

struct CFilePathCT encryptFilepath(char *pk, char *filepath);

struct CFileCT encryptNewFile(char **pks,
                              size_t num_pk,
                              char *filepath,
                              struct CContentsBytes contents);

char *encryptNewFileWithSharedKey(struct CRecoveredSharedKey recovered_shared_key,
                                  struct CContentsBytes contents);

char *genAuthorizationSeed(void);

struct CReadPermissionCT genReadPermissionCT(char *pk,
                                             struct CRecoveredSharedKey recovered_shared_key,
                                             char *filepath);

char *pkeGenPublicKey(char *sk);

char *pkeGenSecretKey(void);

char *pkeGenSignature(char *sk,
                      char *region_name,
                      char *method,
                      char *uri,
                      int nonce,
                      char **fields,
                      char **vals,
                      size_t num_field);

struct CRecoveredSharedKey recoverSharedKey(char *sk, struct CSharedKeyCT ct);

int verifySignature(char *pk,
                    char *region_name,
                    char *method,
                    char *uri,
                    int nonce,
                    char **fields,
                    char **vals,
                    size_t num_field,
                    char *signature);
