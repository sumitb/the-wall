#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <strsafe.h>
#include <detours.h>
#include <DbgHelp.h>

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "ws2_32.lib")

HANDLE hFile;
char* logFile = "C:\\Users\\sbindal\\vs2013\\Projects\\cse523\\Release\\log.txt";

void __cdecl logger(char DataBuffer[])
{
	DWORD dwBytesToWrite = (DWORD)strlen(DataBuffer);
	DWORD dwBytesWritten = 0;
	BOOL bErrorFlag = FALSE;

	bErrorFlag = WriteFile(
		hFile,           // open file handle
		DataBuffer,      // start of data to write
		dwBytesToWrite,  // number of bytes to write
		&dwBytesWritten, // number of bytes that were written
		NULL);            // no overlapped structure

	_tprintf(TEXT("Wrote %d bytes to %s successfully.\n"), dwBytesWritten, logFile);
}

void printStack(void)
{
	unsigned int   i;
	void         * stack[100];
	unsigned short frames;
	SYMBOL_INFO  * symbol;
	HANDLE         process;
	char		   buffer[100];
	char		   stackBuffer[3000];

	process = GetCurrentProcess();

	SymInitialize(process, NULL, TRUE);

	frames = CaptureStackBackTrace(0, 100, stack, NULL);
	symbol = (SYMBOL_INFO *)calloc(sizeof(SYMBOL_INFO) + 256 * sizeof(char), 1);
	symbol->MaxNameLen = 255;
	symbol->SizeOfStruct = sizeof(SYMBOL_INFO);

	for (i = 0; i < frames; i++)
	{
		SymFromAddr(process, (DWORD64)(stack[i]), 0, symbol);

		sprintf_s(buffer, "%i: %s - 0x%0X\n", frames - i - 1, symbol->Name, symbol->Address);
		strcat_s(stackBuffer, buffer);
	}
	//MessageBoxA(NULL, stackBuffer, "Stack Trace", MB_OK);
	free(symbol);
}

static VOID Decode(PBYTE pbCode, LONG nInst)
{
	PBYTE pbSrc = pbCode;
	PBYTE pbEnd;
	PBYTE pbTarget;
	for (LONG n = 0; n < nInst; n++) {
		pbTarget = NULL;
		pbEnd = (PBYTE)DetourCopyInstruction(NULL, NULL, (PVOID)pbSrc, (PVOID*)&pbTarget, NULL);
		//Dump(pbSrc, (int)(pbEnd - pbSrc), pbTarget);
		pbSrc = pbEnd;

		if (pbTarget != NULL) {
			break;
		}
	}
}

VOID DetAttach(PVOID *ppvReal, PVOID pvMine, PCHAR psz)
{
	PVOID pvReal = NULL;
	if (ppvReal == NULL) {
		ppvReal = &pvReal;
	}

	LONG l = DetourAttach(ppvReal, pvMine);
	if (l != 0) {
		Decode((PBYTE)*ppvReal, 3);
	}
}

VOID DetDetach(PVOID *ppvReal, PVOID pvMine, PCHAR psz)
{
	LONG l = DetourDetach(ppvReal, pvMine);
	if (l != 0) {
		(void)psz;
	}
}

#define ATTACH(x)       DetAttach(&(PVOID&)Real_##x,Mine_##x,#x)
#define DETACH(x)       DetDetach(&(PVOID&)Real_##x,Mine_##x,#x)

static LONG dwSlept = 0;

// Target pointer for the uninstrumented Sleep API.
//
static VOID(WINAPI * TrueSleep)(DWORD dwMilliseconds) = Sleep;

// Detour function that replaces the Sleep API.
//
VOID WINAPI TimedSleep(DWORD dwMilliseconds)
{
	// Save the before and after times around calling the Sleep API.
	DWORD dwBeg = GetTickCount64();
	TrueSleep(dwMilliseconds);
	DWORD dwEnd = GetTickCount64();

	InterlockedExchangeAdd(&dwSlept, dwEnd - dwBeg);
}

///////////////////////////////////////////////////////////////// Trampolines.
//
FARPROC(__stdcall * Real_GetProcAddress)(HMODULE a0,
	LPCSTR a1)
	= GetProcAddress;

HMODULE(__stdcall * Real_LoadLibraryA)(LPCSTR a0)
= LoadLibraryA;

HMODULE(__stdcall * Real_LoadLibraryExA)(LPCSTR a0,
	HANDLE a1,
	DWORD a2)
	= LoadLibraryExA;

HMODULE(__stdcall * Real_LoadLibraryExW)(LPCWSTR a0,
	HANDLE a1,
	DWORD a2)
	= LoadLibraryExW;

HMODULE(__stdcall * Real_LoadLibraryW)(LPCWSTR a0)
= LoadLibraryW;

LPVOID(__stdcall * Real_VirtualAlloc)(LPVOID a0,
	SIZE_T a1,
	DWORD a2,
	DWORD a3)
	= VirtualAlloc;

LPVOID(__stdcall * Real_VirtualAllocEx)(HANDLE a0,
	LPVOID a1,
	SIZE_T a2,
	DWORD a3,
	DWORD a4)
	= VirtualAllocEx;

BOOL(__stdcall * Real_VirtualProtect)(LPVOID a0,
	SIZE_T a1,
	DWORD a2,
	PDWORD a3)
	= VirtualProtect;

BOOL(__stdcall * Real_VirtualProtectEx)(HANDLE a0,
	LPVOID a1,
	SIZE_T a2,
	DWORD a3,
	PDWORD a4)
	= VirtualProtectEx;

///////////////////////////////////////////////////////////////////// Detours.
//
FARPROC __stdcall Mine_GetProcAddress(HMODULE a0,
	LPCSTR a1)
{
	static int count = 1;
	//_PrintEnter("GetProcAddress(%p,%hs)\n", a0, a1);
	//MessageBoxA(NULL, "GetProcAddress hook!!", "Hook Message", MB_OK);
	//logger((LPSTR)count);
	//logger(". GetProcAddress hook!!\n");
	FARPROC rv = 0;
	__try {
		rv = Real_GetProcAddress(a0, a1);
	}
	__finally {
		//_PrintExit("GetProcAddress(,) -> %p\n", rv);
	};
	count++;
	return rv;
}

HMODULE __stdcall Mine_LoadLibraryA(LPCSTR a0)
{
	//_PrintEnter("LoadLibraryA(%hs)\n", a0);
	//MessageBoxA(NULL, "LoadLibraryA hook!!", "Hook Message", MB_OK);
	HMODULE rv = 0;
	__try {
		rv = Real_LoadLibraryA(a0);
	}
	__finally {
		//_PrintExit("LoadLibraryA() -> %p\n", rv);
	};
	return rv;
}

HMODULE __stdcall Mine_LoadLibraryExA(LPCSTR a0,
	HANDLE a1,
	DWORD a2)
{
	//_PrintEnter("LoadLibraryExA(%hs,%p,%p)\n", a0, a1, a2);
	//MessageBoxA(NULL, "LoadLibraryExA hook!!", "Hook Message", MB_OK);
	HMODULE rv = 0;
	__try {
		rv = Real_LoadLibraryExA(a0, a1, a2);
	}
	__finally {
		//_PrintExit("LoadLibraryExA(,,) -> %p\n", rv);
	};
	return rv;
}

HMODULE __stdcall Mine_LoadLibraryExW(LPCWSTR a0,
	HANDLE a1,
	DWORD a2)
{
	//_PrintEnter("LoadLibraryExW(%ls,%p,%p)\n", a0, a1, a2);
	//MessageBoxA(NULL, "LoadLibraryExW hook!!", "Hook Message", MB_OK);
	HMODULE rv = 0;
	__try {
		rv = Real_LoadLibraryExW(a0, a1, a2);
	}
	__finally {
		//_PrintExit("LoadLibraryExW(,,) -> %p\n", rv);
	};
	return rv;
}

HMODULE __stdcall Mine_LoadLibraryW(LPCWSTR a0)
{
	//_PrintEnter("LoadLibraryW(%ls)\n", a0);
	//MessageBoxA(NULL, "LoadLibraryW hook!!", "Hook Message", MB_OK);
	HMODULE rv = 0;
	__try {
		rv = Real_LoadLibraryW(a0);
	}
	__finally {
		//_PrintExit("LoadLibraryW() -> %p\n", rv);
	};
	return rv;
}

LPVOID __stdcall Mine_VirtualAlloc(LPVOID a0,
	SIZE_T a1,
	DWORD a2,
	DWORD a3)
{
	//MessageBoxA(NULL, "VirtualAlloc hook!!", "Hook Message", MB_OK);
	LPVOID rv = 0;
	rv = Real_VirtualAlloc(a0, a1, a2, a3);
	return rv;
}

LPVOID __stdcall Mine_VirtualAllocEx(HANDLE a0,
	LPVOID a1,
	SIZE_T a2,
	DWORD a3,
	DWORD a4)
{
	//_PrintEnter("VirtualAllocEx(%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4);
	//MessageBoxA(NULL, "VirtualAllocEx hook!!", "Hook Message", MB_OK);
	LPVOID rv = 0;
	__try {
		rv = Real_VirtualAllocEx(a0, a1, a2, a3, a4);
	}
	__finally {
		//_PrintExit("VirtualAllocEx(,,,,) -> %p\n", rv);
	};
	return rv;
}

BOOL __stdcall Mine_VirtualProtect(LPVOID a0,
	SIZE_T a1,
	DWORD a2,
	PDWORD a3)
{
	//_PrintEnter("VirtualProtectEx(%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4);
	//MessageBoxA(NULL, "VirtualProtect hook!!", "Hook Message", MB_OK);
	printStack();
	BOOL rv = 0;
	__try {
		rv = Real_VirtualProtect(a0, a1, a2, a3);
	}
	__finally {
		//_PrintExit("VirtualProtectEx(,,,,) -> %p\n", rv);
	};
	return rv;
}

BOOL __stdcall Mine_VirtualProtectEx(HANDLE a0,
	LPVOID a1,
	SIZE_T a2,
	DWORD a3,
	PDWORD a4)
{
	//_PrintEnter("VirtualProtectEx(%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4);
	//MessageBoxA(NULL, "VirtualProtectEx hook!!", "Hook Message", MB_OK);
	BOOL rv = 0;
	__try {
		rv = Real_VirtualProtectEx(a0, a1, a2, a3, a4);
	}
	__finally {
		//_PrintExit("VirtualProtectEx(,,,,) -> %p\n", rv);
	};
	return rv;
}

// DllMain function attaches and detaches the TimedSleep detour to the
// Sleep target function.  The Sleep target function is referred to
// through the TrueSleep target pointer.
//
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{ 	
	if (DetourIsHelperProcess()) {
		return TRUE;
	}
	
	hFile = CreateFile(logFile,                // name of the write
		GENERIC_WRITE,          // open for writing
		FILE_SHARE_WRITE,       // share for writing
		NULL,                   // default security
		OPEN_ALWAYS,            // open file only
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);                  // no attr. template

	_tprintf(TEXT("Start of log file @ %s.\n"), logFile);
	

	if (dwReason == DLL_PROCESS_ATTACH) {	
		DetourRestoreAfterWith();

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)TrueSleep, TimedSleep);
		ATTACH(GetProcAddress);
		ATTACH(LoadLibraryA);
		ATTACH(LoadLibraryExA);
		ATTACH(LoadLibraryExW);
		ATTACH(LoadLibraryW);
		ATTACH(VirtualAlloc);
		ATTACH(VirtualAllocEx);
		ATTACH(VirtualProtect);
		ATTACH(VirtualProtectEx);
		DetourTransactionCommit();
	}
	else if (dwReason == DLL_PROCESS_DETACH) {
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)TrueSleep, TimedSleep);
		DETACH(GetProcAddress);
		DETACH(LoadLibraryA);
		DETACH(LoadLibraryExA);
		DETACH(LoadLibraryExW);
		DETACH(LoadLibraryW);
		DETACH(VirtualAlloc);
		DETACH(VirtualAllocEx);
		DETACH(VirtualProtect);
		DETACH(VirtualProtectEx);
		DetourTransactionCommit();
		//CloseHandle(hFile);
	}
	return TRUE;
}

extern "C" __declspec(dllexport) void dummy(void){
	return;
}