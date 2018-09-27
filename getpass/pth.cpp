#include "stdafx.h"
#include "pth.h"

//返回token的AuthenticationId低位
BOOL LogonWithNewCredential(LPDWORD lpLowPart)
{
	LPWSTR lpDomain = NULL;// L"10.92.53.98"; 不需要域名参数，为NULL即可
	LPWSTR lpUsername = L"Administrator";
	LPWSTR lpPassword = L"anything";

	//使用LOGON32_LOGON_NEW_CREDENTIALS调用LogonUser，同runas的/netonly
	HANDLE hToken = NULL;
	BOOL bRet = LogonUserW(lpUsername, lpUsername, lpPassword,
		LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, &hToken);
	RETN_IF(!bRet, L"LogonUserW", FALSE);

	//复制模拟令牌
	HANDLE hDupToken = NULL;
	bRet = DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDupToken);
	RETN_IF(!bRet, L"DuplicateToken", FALSE);

	CloseHandle(hToken);

	//读取令牌信息
	TOKEN_STATISTICS szTokenStatistics = { 0 };
	DWORD cbData = 0;
	bRet = GetTokenInformation(hDupToken, TokenStatistics, &szTokenStatistics, sizeof(szTokenStatistics), &cbData);
	RETN_IF(!bRet, L"GetTokenInformation", FALSE);

	MESSAGE(L"Token AuthenticationId:%d %d\r\n", szTokenStatistics.AuthenticationId.HighPart, szTokenStatistics.AuthenticationId.LowPart);
	*lpLowPart = szTokenStatistics.AuthenticationId.LowPart;
	//使用模拟令牌创建进程。在新进程里面可进行远程DCOM调用
	STARTUPINFOW StartupInfo = { 0 };
	{
		StartupInfo.cb = sizeof(STARTUPINFO);
		StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
		StartupInfo.wShowWindow = TRUE;
	}
	PROCESS_INFORMATION ProcessInformation = { 0 };

	bRet = CreateProcessWithTokenW(hDupToken, LOGON_NETCREDENTIALS_ONLY, NULL, L"powershell.exe", CREATE_NEW_CONSOLE, NULL, NULL, &StartupInfo, &ProcessInformation);
	RETN_IF(!bRet, L"CreateProcessWithTokenW", FALSE);

	return TRUE;
}

