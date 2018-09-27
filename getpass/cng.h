#pragma once
#include <Windows.h>
#include <bcrypt.h>
#include "common.h"

// struct from mimikatz
#define MAX_KEY_SIZE 64

typedef struct _KIWI_HARD_KEY {
	ULONG cbSecret;
	BYTE  data[MAX_KEY_SIZE]; // etc...
} KIWI_HARD_KEY, *PKIWI_HARD_KEY;

typedef struct _KIWI_BCRYPT_KEY {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY, *PKIWI_BCRYPT_KEY;

typedef struct _KIWI_BCRYPT_HANDLE_KEY {
	ULONG size;
	ULONG tag;	// 'UUUR'
	PVOID hAlgorithm;
	PKIWI_BCRYPT_KEY key;
	PVOID unk0;
} KIWI_BCRYPT_HANDLE_KEY, *PKIWI_BCRYPT_HANDLE_KEY;

typedef struct _KIWI_BCRYPT_KEY8 {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	ULONG unk3;
	PVOID unk4;	// before, align in x64
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY8, *PKIWI_BCRYPT_KEY8;

typedef struct _KIWI_BCRYPT_KEY81 { //windows 10
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	ULONG unk3;
	ULONG unk4;
	PVOID unk5;	// before, align in x64
	ULONG unk6;
	ULONG unk7;
	ULONG unk8;
	ULONG unk9;
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY81, *PKIWI_BCRYPT_KEY81;

BOOL DesDecrypt(IN LPBYTE lpEncryptPassword, IN DWORD cbEncryptPassword,
	IN LPBYTE lpKey, IN DWORD cbKey, IN LPBYTE lpIV,
	IN DWORD cbIV, OUT LPBYTE lpPlainOutput, OUT DWORD cbPlainOutput);
BOOL AesDecrypt(IN LPBYTE lpEncryptBuf, IN DWORD cbEncryptPassword,
	IN LPBYTE lpKey, IN DWORD cbKey, IN LPBYTE lpIV,
	IN DWORD cbIV, OUT LPBYTE lpPlainOutput, OUT DWORD cbPlainOutput);
BOOL DesEncrypt(IN LPBYTE lpEncryptBuf, IN DWORD cbEncryptPassword,
	IN LPBYTE lpKey, IN DWORD cbKey, IN LPBYTE lpIV,
	IN DWORD cbIV, OUT LPBYTE lpPlainOutput, OUT DWORD cbPlainOutput);