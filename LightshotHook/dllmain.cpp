#include "dllmain.hpp"
#include <stdio.h>
#include <string>
#include <shlobj.h>
#include "MinHook.h"
#include <sys/stat.h>

HANDLE g_HProc = NULL;
wchar_t g_ServerAddress[127] = L"https://upload.prntscr.com/upload";

/*
trecv t_recv = NULL;
tInternetReadFile t_InternetReadFile = NULL;
*/

MH_STATUS HookFunc(LPCWSTR label, LPVOID pTarget, LPVOID pDetour, LPVOID* ppOriginal)
{
	wprintf(L"Original %s: 0x%llx\n", label, (uint64_t)pTarget);

	MH_STATUS status = MH_CreateHook(pTarget, pDetour, ppOriginal);
	if (status != MH_OK)
	{
		wprintf(L"Failed to create hook for %s: %S\n", label, MH_StatusToString(status));
		return status;
	}

	status = MH_EnableHook(pTarget);
	if (status != MH_OK)
	{
		wprintf(L"Failed to enable hook for %s: %S\n", label, MH_StatusToString(status));
		return status;
	}

	wprintf(L"Succes hooking %s\n", label);


	return status;
}

uint8_t* ScanMemory(uint32_t base, MEMORY_SCAN_ROUTINE fn)
{
	MEMORY_BASIC_INFORMATION mbi;
	uint32_t curr = base;
	while (VirtualQueryEx(g_HProc, (LPCVOID)curr, &mbi, sizeof(mbi)) != 0)
	{
		if ((mbi.State & MEM_COMMIT) && (mbi.Protect & MEM_ALL_READABLE) && !(mbi.Protect & PAGE_GUARD))
		{
			uint8_t* off = fn(curr, mbi.RegionSize);
			if (off != nullptr)
			{
				return off;
			}
		}
		curr = curr + mbi.RegionSize;
	}
	return nullptr;
}

uint8_t* FindString(uint32_t base, const wchar_t* str)
{
	size_t sz = wcslen(str) * sizeof(wchar_t);

	return ScanMemory(base, [str, sz](uint32_t curr, size_t size)
	{
		for (uint32_t i = 0; i < size - sz; i++)
		{
			uint8_t* off = (uint8_t*)(curr + i);
			if (memcmp(str, off, sz) == 0)
			{
				return off;
			}
		}
		return (uint8_t*)nullptr;
	});
}
/*
int WINAPI hk_recv(SOCKET socket, char* buff, int len, int flags)
{
	printf("recv\n");

	int ret = t_recv(socket, buff, len, flags);
	
	for (int i = 0; i < len; i++)
	{
		printf("%c", buff[i]);
	}

	printf("\n");

	return ret;
}

BOOL WINAPI hk_InternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead)
{
	printf("InternetReadFile\n");

	BOOL ret = t_InternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);

	if (!ret)
		return false;

	auto data = (const char*)lpBuffer;
	int read = *lpdwNumberOfBytesRead;
	
	for (int i = 0; i < read; i++)
	{
		printf("%c", data[i]);
	}

	return true;
}
*/
void EnablePatches()
{
	wprintf(L"enabling patches\n");

	// Find server url offset
	auto hdl = (uint32_t)LoadLibraryA("uploader.dll");
	auto addr = (uint32_t)FindString((hdl), L"https://upload.prntscr.com");

	if (addr == 0) // Wrong executable (launcher)
	{
		return;
	}

	// Find PUSH <server url offset> instruction
	uint8_t* search = ScanMemory(hdl, [&](uint32_t curr, size_t size)
	{
		for (uint32_t i = 0; i < size - 5; i++)
		{
			uint8_t*  off  = (uint8_t* )(curr + i);
			uint32_t* off2 = (uint32_t*)(curr + i + 1);

			if ((*off == 0x68) && (*off2 == addr))
			{
				return (uint8_t*)off2;
			}

		}
		return (uint8_t*)nullptr;
	});

	// Replace server url offset in PUSH instruction by g_ServerAddress offset
	DWORD oldProtect;
	VirtualProtect(search, sizeof(uint32_t), PAGE_EXECUTE_READWRITE, &oldProtect);
	*(uint32_t*)search = (uint32_t)g_ServerAddress;
	VirtualProtect(search, sizeof(uint32_t), oldProtect, &oldProtect);
	
	//HookFunc(L"recv", &recv, &hk_recv, reinterpret_cast<LPVOID*>(&t_recv));
	//HookFunc(L"InternetReadFile", &InternetReadFile, &hk_InternetReadFile, reinterpret_cast<LPVOID*>(&t_InternetReadFile));
	
}

void Main()
{
	g_HProc = GetCurrentProcess();
	
	/*
	AllocConsole();
	AttachConsole(GetCurrentProcessId());

	freopen("CON", "w", stdout);
	freopen("CONIN$", "r", stdin);

	wprintf(L"console acquired\n");

	MH_STATUS status = MH_Initialize();
	*/

	// Read address from My Documents\lightshot.txt (create if not exists)
	char MyDocuments[MAX_PATH];
	HRESULT result = SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, SHGFP_TYPE_CURRENT, MyDocuments);

	std::string path(MyDocuments);
	path += "\\lightshot.txt";

	struct stat buffer;
	char address[255];

	wcstombs(address, g_ServerAddress, 255);

	if (stat(path.c_str(), &buffer) == 0)
	{
		FILE* f = fopen(path.c_str(), "r");
		int len = fread(address, sizeof(char), sizeof(address), f);
		fclose(f);
		address[strcspn(address, "\r\n")] = '\0';
		ZeroMemory(g_ServerAddress, sizeof(g_ServerAddress));
		mbstowcs(g_ServerAddress, address, len);
	}
	else
	{
		FILE* f = fopen(path.c_str(), "w");
		fwrite(address, sizeof(char), strlen(address), f);
		fclose(f);
	}

	EnablePatches();

}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		Main();
		break;
	}
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		//MH_DisableHook(MH_ALL_HOOKS);
		//MH_Uninitialize();
		break;
	}
	return TRUE;
}

