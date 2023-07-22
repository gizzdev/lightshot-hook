#pragma once
#pragma warning( disable : 6031 6273 6387 26819 )
#include "windows.h"
#include <vector>

extern uint64_t g_LoadLibraryAddress;

DWORD GetProcessIdByName(LPCWSTR name, std::vector<DWORD> ignore);

BOOL InjectDLL(DWORD procID, LPCSTR dllPath);

DWORD WaitAndInject(LPCWSTR name, LPCSTR dllPath);

