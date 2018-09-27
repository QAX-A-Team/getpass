#pragma once
#include "common.h"
#include <TlHelp32.h>

typedef NTSTATUS(*fnRtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);

BOOL    EnableDebugPrivilege();
DWORD   GetProcessIdByName(IN LPCWSTR lpProcName);
HANDLE  OpenProcessByName(IN LPCWSTR lpProcName, OUT LPDWORD lpProcId);
ULONG64 GetModuleVersion(IN HMODULE hModule);
LPVOID  FindPattern(IN LPVOID lpStart, IN LPVOID lpEnd, IN ULONG64 ulPattern);
LPVOID  FindPattern(IN LPVOID lpStart, IN UCHAR ucTag, IN ULONG64 ulPattern);
LPVOID  FindPatternFromModule(IN HMODULE hModule, IN PIMAGE_PATTERN lpPattern,
	IN LPVOID lpStart, IN LPVOID lpEnd, IN BYTE ucTag);
VOID    HexDump(IN LPBYTE lpPtr, IN DWORD dwSize, IN BOOL bNewline);
VOID    DigestDump(IN LPBYTE lpPtr, IN DWORD dwSize);
BOOL    OpenLsass();
BOOL    ReadLsassMemory(IN LPVOID lpPtr, OUT LPVOID lpBuf, IN DWORD cbBuf);
BOOL    WriteLsassMemory(IN LPVOID lpPtr, OUT LPVOID lpBuf, IN DWORD cbBuf);
VOID    CloseLsass();