#pragma once
#pragma warning( disable : 6031 6273 6387 26819 )
#include <Windows.h>
#include <inttypes.h>
#include <wininet.h>
#include <ws2tcpip.h>
#include <functional>

const DWORD MEM_ALL_READABLE = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

typedef std::function<uint8_t*(uint32_t, size_t)> MEMORY_SCAN_ROUTINE;

// typedef int (WINAPI* trecv)(SOCKET, char*, int, int);
// typedef BOOL(WINAPI* tInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);

