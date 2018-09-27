#pragma once
#include "common.h"
#include "cng.h"

typedef struct _BCRYPT_GEN_KEY {
	BCRYPT_ALG_HANDLE hProvider;
	BCRYPT_KEY_HANDLE hKey;
	PBYTE pKey;
	ULONG cbKey;
} BCRYPT_GEN_KEY, *PBCRYPT_GEN_KEY;

BOOL FindBcryptKeys();
BOOL LsaEncryptMemory(IN OUT LPBYTE lpBuf, IN DWORD cbBuf, IN INT unused);