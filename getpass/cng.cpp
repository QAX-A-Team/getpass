#include "stdafx.h"
#include "cng.h"

#pragma comment(lib, "Bcrypt.lib")

BOOL DesDecrypt(IN LPBYTE lpEncryptBuf, IN DWORD cbEncryptPassword,
	IN LPBYTE lpKey, IN DWORD cbKey, IN LPBYTE lpIV,
	IN DWORD cbIV, OUT LPBYTE lpPlainOutput, OUT DWORD cbPlainOutput)
{
	BCRYPT_ALG_HANDLE hBcryptALG = NULL;
	BCRYPT_KEY_HANDLE hDesKey = NULL;
	DWORD cbData = 0;
	NTSTATUS status;

	if (NT_ERROR(status = BCryptOpenAlgorithmProvider(&hBcryptALG, BCRYPT_3DES_ALGORITHM, NULL, 0)))
	{
		fwprintf(stderr, L"BCryptOpenAlgorithmProvider: [%x]\r\n", status);
		return FALSE;
	}

	//设置CBC填充模式
	if (NT_ERROR(status = BCryptSetProperty(hBcryptALG, BCRYPT_CHAINING_MODE,
		(LPBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0)))
	{
		fwprintf(stderr, L"BCryptSetProperty: BCRYPT_CHAINING_MODE [%x]\r\n", status);
		return FALSE;
	}

	if (NT_ERROR(status = BCryptGenerateSymmetricKey(hBcryptALG, &hDesKey, NULL,
		0, lpKey, cbKey, 0)))
	{
		fwprintf(stderr, L"BCryptGenerateSymmetricKey [%x]\r\n", status);
		return FALSE;
	}

	//解密
	if (NT_ERROR(status = BCryptDecrypt(hDesKey, lpEncryptBuf, cbEncryptPassword,
		NULL, lpIV, cbIV, lpPlainOutput,
		cbPlainOutput, &cbData, 0))) //最后一个参数必须为0，默认使用Zero填充
	{
		fwprintf(stderr, L"BCryptDecrypt [%x]\r\n", status);
		return FALSE;
	}

	return TRUE;
}
