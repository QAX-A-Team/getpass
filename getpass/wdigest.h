#pragma once
#include <Windows.h>
#define SECURITY_WIN32
#include <Sspi.h>
#include <Ntsecapi.h>
#include <Ntsecpkg.h>
#pragma warning(disable:4091)
#include "common.h"


typedef struct _KIWI_WDIGEST_LIST_ENTRY {
	struct _KIWI_WDIGEST_LIST_ENTRY *Flink;
	struct _KIWI_WDIGEST_LIST_ENTRY *Blink;
	DWORD	UsageCount;
	struct _KIWI_WDIGEST_LIST_ENTRY *This;
	LUID LocallyUniqueIdentifier;
	DWORD unknown0;
	DWORD unknown1;
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domain;
	LSA_UNICODE_STRING EncryptedPassword;
	LSA_UNICODE_STRING DnsDomain;
	//more structure unknowned
} KIWI_WDIGEST_LIST_ENTRY, *PKIWI_WDIGEST_LIST_ENTRY;

BOOL Wdigest_LogSessList_Dump(IN HANDLE hLsass, IN LPBYTE lpKey, IN DWORD cbKey,
	IN LPBYTE lpIV, IN DWORD cbIV);
