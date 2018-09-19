#pragma once

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#ifndef NT_ERROR
#define NT_ERROR(Status) ((ULONG)(Status) >> 30 == 3)
#endif

#define RETN_IF(cond, func, val) if(cond) \
{\
	fwprintf(stderr, L"File:%hs Line:%d Function:%hs Api:%s Code:%d\r\n",  \
	__FILE__, __LINE__, __FUNCTION__, func, GetLastError()); \
	return val; \
}

#define RETN_MSG_IF(cond, val, ...) if(cond) \
{\
	fwprintf(stderr, __VA_ARGS__); \
	return val; \
}

#define GOTO_IF(cond, func, label) if(cond) \
{\
	fwprintf(stderr, L"File:%hs Line:%d Function:%hs Api:%s Code:%d\r\n",  \
	__FILE__, __LINE__, __FUNCTION__, func, GetLastError()); \
	goto label; \
}

#define GOTO_MSG_IF(cond, label, ...) if(cond) \
{\
	fwprintf(stderr, __VA_ARGS__); \
	goto label; \
}

#define MESSAGE(...) fwprintf(stdout, __VA_ARGS__);

typedef struct _IMAGE_PATTERN
{
	ULONG64 version; //文件版本
	ULONG64 sign;    //8字节的搜索字符串，LSB成一个ULONG64
	INT     offset;  //找到pattren后目标地址偏移,0xFF代表是一个相对基地址偏移
} IMAGE_PATTERN, *PIMAGE_PATTERN;
