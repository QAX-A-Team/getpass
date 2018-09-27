#pragma once
#define SECURITY_WIN32
#include <Sspi.h>
#include <Ntsecapi.h>
#include <Ntsecpkg.h>
#include "common.h"


//from mimikatz
typedef struct _KIWI_GENERIC_PRIMARY_CREDENTIAL
{
	//win10 x64，测试时domain和username位置不同，进行了对调
	LSA_UNICODE_STRING Domain;
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Password;
} KIWI_GENERIC_PRIMARY_CREDENTIAL, *PKIWI_GENERIC_PRIMARY_CREDENTIAL;

typedef struct _KIWI_TS_PRIMARY_CREDENTIAL {
	PVOID unk0;	// lock ?
	KIWI_GENERIC_PRIMARY_CREDENTIAL credentials;
} KIWI_TS_PRIMARY_CREDENTIAL, *PKIWI_TS_PRIMARY_CREDENTIAL;

typedef struct _KIWI_TS_CREDENTIAL {
#ifdef _M_X64
	BYTE unk0[108];
#elif defined _M_IX86
	BYTE unk0[64];
#endif
	LUID LocallyUniqueIdentifier;
	PVOID unk1;
	PVOID unk2;
	PKIWI_TS_PRIMARY_CREDENTIAL pTsPrimary;
} KIWI_TS_CREDENTIAL, *PKIWI_TS_CREDENTIAL;

typedef struct _KIWI_TS_CREDENTIAL_1607 {
#ifdef _M_X64
	BYTE unk0[112];
#elif defined _M_IX86
	BYTE unk0[68];
#endif
	LUID LocallyUniqueIdentifier;
	PVOID unk1;
	PVOID unk2;
	PKIWI_TS_PRIMARY_CREDENTIAL pTsPrimary;
} KIWI_TS_CREDENTIAL_1607, *PKIWI_TS_CREDENTIAL_1607;

//from ntddk.h
typedef struct _RTL_BALANCED_LINKS {
	struct _RTL_BALANCED_LINKS *Parent;
	struct _RTL_BALANCED_LINKS *LeftChild;
	struct _RTL_BALANCED_LINKS *RightChild;
	CHAR Balance;
	UCHAR Reserved[3]; // align
} RTL_BALANCED_LINKS, *PRTL_BALANCED_LINKS;

typedef struct _RTL_AVL_TABLE {
	RTL_BALANCED_LINKS BalancedRoot;
	PVOID OrderedPointer;
	ULONG WhichOrderedElement;
	ULONG NumberGenericTableElements;
	ULONG DepthOfTree;
	PRTL_BALANCED_LINKS RestartKey;
	ULONG DeleteCount;
	PVOID CompareRoutine; 
	PVOID AllocateRoutine;
	PVOID FreeRoutine;
	PVOID TableContext;
} RTL_AVL_TABLE, *PRTL_AVL_TABLE;

BOOL Tspkg_TSGlobalCredTable_Dump();
extern BOOL ReadLsassLSAString(IN PLSA_UNICODE_STRING lpUStr, OUT LPBYTE lpBuff);
extern BOOL ReadLsassLSABuffer(IN PLSA_UNICODE_STRING lpUStr, OUT LPBYTE lpBuff);
extern BOOL LsaEncryptMemory(IN OUT LPBYTE lpBuf, IN DWORD cbBuf, IN INT unused);