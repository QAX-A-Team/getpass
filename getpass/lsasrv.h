#pragma once
#include "common.h"
#include "cng.h"
BOOL FindH3DesKey(IN HANDLE hLsass, OUT PKIWI_HARD_KEY lp3DesKey,
	OUT LPBYTE lpIV, OUT LPDWORD lpcbIV);
