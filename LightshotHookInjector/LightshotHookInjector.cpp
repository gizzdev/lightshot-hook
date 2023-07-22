#include "main.hpp"
#include <stdio.h>
#include <filesystem>
#include <tlhelp32.h>

uint64_t g_LoadLibraryAddress;

DWORD GetProcessIdByName(LPCWSTR name, std::vector<DWORD> ignore = {})
{
	PROCESSENTRY32 pt;
	HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pt.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hsnap, &pt)) {
		do {
			if ((!lstrcmpi(pt.szExeFile, name)) && (std::find(ignore.begin(), ignore.end(), pt.th32ProcessID) == ignore.end()))
			{
				CloseHandle(hsnap);
				return pt.th32ProcessID;
			}
		} while (Process32Next(hsnap, &pt));
	}
	CloseHandle(hsnap);
	return 0;
}

BOOL InjectDLL(DWORD procID, LPCSTR dllPath)
{
	BOOL WPM = 0;
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, procID);
	if (hProc == INVALID_HANDLE_VALUE)
	{
		wprintf(L"error while opening process");
		return FALSE;
	}

	size_t dllPathSize = strlen(dllPath);
	LPVOID dllPathAddressInRemoteMemory = VirtualAllocEx(hProc, nullptr, dllPathSize + 1, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	BOOL succeededWriting = WriteProcessMemory(hProc, dllPathAddressInRemoteMemory, dllPath, dllPathSize, NULL);
	if (!succeededWriting)
	{
		wprintf(L"error while writing process memory\n");
		return FALSE;
	}

	wprintf(L"LoadLibraryA: 0x%llx\n", g_LoadLibraryAddress);

	LPVOID hThread = CreateRemoteThread(hProc, nullptr, NULL, (LPTHREAD_START_ROUTINE)g_LoadLibraryAddress, dllPathAddressInRemoteMemory, 0, nullptr);
	if (hThread == NULL)
	{
		wprintf(L"error while creating remote thread\n");
		return FALSE;
	}

	wprintf(L"Thread id: 0x%llx\n", (uint64_t)hThread);

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);

	VirtualFreeEx(hProc, dllPathAddressInRemoteMemory, 0, MEM_RELEASE);
	CloseHandle(hProc);

	return TRUE;
}
DWORD WaitAndInject(LPCWSTR name, LPCSTR dllPath)
{
	std::vector<DWORD> pids = {};
	DWORD pid = 0;
	DWORD lastPid = 0;
	while (TRUE)
	{
		while ((pid == 0) || (pid == lastPid))
		{
			pid = GetProcessIdByName(name, pids);
		}
		if (pid != 0)
		{
			wprintf(L"Injecting DLL to %s PID: 0x%x\n", name, pid);

			InjectDLL(pid, dllPath);

			pids.push_back(pid);
			lastPid = pid;
		}
		Sleep(10);
	}
}

int main(int argc, char* argv[])
{
	ShowWindow(::GetConsoleWindow(), SW_HIDE);

	auto dllPath = (std::filesystem::current_path() / L"LightshotHook.dll").string();

	g_LoadLibraryAddress = (uint32_t)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");

	WaitAndInject(L"Lightshot.exe", dllPath.c_str());

	return 0;
}