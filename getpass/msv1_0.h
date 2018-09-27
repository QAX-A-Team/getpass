#pragma once
#include <Windows.h>
#define SECURITY_WIN32
#include <Sspi.h>
#include <Ntsecapi.h>
#include <Ntsecpkg.h>

#define UUUR_TAG 0x55555552
#define MSSK_TAG 0x4d53534b
#define KSSM UUUR_TAG

#define LM_NTLM_HASH_LENGTH	16
#define SHA_DIGEST_LENGTH	20

typedef struct _MSV1_0_PRIMARY_CREDENTIAL_10_1607 {
	//copy from mimika ,win10 1709
	LSA_UNICODE_STRING LogonDomainName;
	LSA_UNICODE_STRING UserName;
	PVOID pNtlmCredIsoInProc;
	BOOLEAN isIso;
	BOOLEAN isNtOwfPassword;
	BOOLEAN isLmOwfPassword;
	BOOLEAN isShaOwPassword;
	BOOLEAN isDPAPIProtected;
	BYTE align0;
	BYTE align1;
	BYTE align2;
	DWORD unkD; // 1/2
#pragma pack(push, 2)
	WORD isoSize;  // 0000
	BYTE DPAPIProtected[LM_NTLM_HASH_LENGTH];
	DWORD align3; // 00000000
#pragma pack(pop) 
	BYTE NtOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE LmOwfPassword[LM_NTLM_HASH_LENGTH];
	BYTE ShaOwPassword[SHA_DIGEST_LENGTH];
	/* buffer */
} MSV1_0_PRIMARY_CREDENTIAL_10_1607, *PMSV1_0_PRIMARY_CREDENTIAL_10_1607;


typedef struct _MSV1_0_PRIMARY_CREDENTIALS {
	//copy and modifiled from mimika _KIWI_MSV1_0_PRIMARY_CREDENTIALS
	struct _MSV1_0_PRIMARY_CREDENTIALS *next;
	LSA_STRING Primary;
	LSA_UNICODE_STRING Credentials;
} MSV1_0_PRIMARY_CREDENTIALS, *PMSV1_0_PRIMARY_CREDENTIALS;

typedef struct _KIWI_MSV1_0_CREDENTIALS {
	//copy from mimika _KIWI_MSV1_0_CREDENTIALS
	struct _KIWI_MSV1_0_CREDENTIALS *next;
	DWORD AuthenticationPackageId;
	PMSV1_0_PRIMARY_CREDENTIALS PrimaryCredentials;
} MSV1_0_CREDENTIALS, *PMSV1_0_CREDENTIALS;

typedef struct _MSV1_0_SESSION_ENTRY {
	//copy and modified from mimika _KIWI_MSV1_0_LIST_63 , for win10 1709
	struct _MSV1_0_SESSION_ENTRY *Flink;	//off_2C5718
	struct _MSV1_0_SESSION_ENTRY *Blink; //off_277380
	PVOID unk0; // unk_2C0AC8
	ULONG unk1; // 0FFFFFFFFh
	PVOID unk2; // 0
	ULONG unk3; // 0
	ULONG unk4; // 0
	ULONG unk5; // 0A0007D0h
	HANDLE hSemaphore6; // 0F9Ch
	PVOID unk7; // 0
	HANDLE hSemaphore8; // 0FB8h
	PVOID unk9; // 0
	PVOID unk10; // 0
	ULONG unk11; // 0
	ULONG unk12; // 0 
	PVOID unk13; // unk_2C0A28
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	BYTE waza[12]; /// to do (maybe align)
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domain;
	PVOID unk14;
	PVOID unk15;
	LSA_UNICODE_STRING Type;
	PSID  pSid;
	ULONG LogonType;
	PVOID unk18;
	ULONG Session;
	LARGE_INTEGER LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	PMSV1_0_CREDENTIALS Credentials;
	PVOID unk19;
	PVOID unk20;
	PVOID unk21;
	ULONG unk22;
	ULONG unk23;
	ULONG unk24;
	ULONG unk25;
	ULONG unk26;
	PVOID unk27;
	PVOID unk28;
	PVOID unk29;
	PVOID CredentialManager;
} MSV1_0_SESSION_ENTRY, *PMSV1_0_SESSION_ENTRY;


BOOL Msv1_0_LogonSessList_Dump();
VOID MSV1_0_NTLM_Copy(PLSA_UNICODE_STRING lpCredBuffer);
VOID MSV1_0_NTLM_Init(LPBYTE lpNTLM);
extern BOOL ReadLsassLSAString(IN PLSA_UNICODE_STRING lpUStr, OUT LPBYTE lpBuff);
extern BOOL LsaEncryptMemory(IN OUT LPBYTE lpBuf, IN DWORD cbBuf, IN INT unused);