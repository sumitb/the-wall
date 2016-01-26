#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <strsafe.h>
#include <detours.h>
#include <DbgHelp.h>

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "ws2_32.lib")

#define LOG_FILE L"C:\\Users\\sbindal\\vs2013\\Projects\\cse523\\Release\\MyLogFile.txt"

TCHAR logBuffer[MAX_PATH];
void PrintError(LPCTSTR errDesc);

void WriteLog(char* text)
{
	HANDLE hfile = CreateFileW(LOG_FILE, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD written;
	WriteFile(hfile, text, strlen(text), &written, NULL);
	WriteFile(hfile, "\r\n", 2, &written, NULL);
	CloseHandle(hfile);
}

void WriteLog(wchar_t* text)
{
	HANDLE hfile = CreateFileW(LOG_FILE,                // name of the write
	FILE_APPEND_DATA,          // open for writing
	FILE_SHARE_READ,       // share for reading
	NULL,                   // default security
	OPEN_ALWAYS,            // open file only
	FILE_ATTRIBUTE_NORMAL,  // normal file
	NULL);                  // no attr. template

	DWORD written;
	WriteFile(hfile, text, wcslen(text) * 2, &written, NULL);
	WriteFile(hfile, L"\r\n", 4, &written, NULL);
	CloseHandle(hfile);
}

void EnableLogger(void) 
{
	// sprintf_s(logBuffer, TEXT("Start of log file."));
	unsigned long long before = GetTickCount();
	sprintf_s(logBuffer, "Process start at %llu" , before);
	WriteLog(logBuffer);
}

/*
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

	sprintf_s(logBuffer, TEXT("Wrote %d bytes to %s successfully.\n"), dwBytesWritten, logFile);
	WriteLog(logBuffer);
}
*/

//  ErrorMessage support function.
//  Retrieves the system error message for the GetLastError() code.
//  Note: caller must use LocalFree() on the returned LPCTSTR buffer.
LPCTSTR ErrorMessage(DWORD error)
{
	LPVOID lpMsgBuf;

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER
		| FORMAT_MESSAGE_FROM_SYSTEM
		| FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		error,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0,
		NULL);

	return((LPCTSTR)lpMsgBuf);
}

//  PrintError support function.
//  Simple wrapper function for error output.
void PrintError(LPCTSTR errDesc)
{
	LPCTSTR errMsg = ErrorMessage(GetLastError());
	sprintf_s(logBuffer, TEXT("\n** ERROR ** %s: %s\n"), errDesc, errMsg);
	WriteLog(logBuffer);
	LocalFree((LPVOID)errMsg);
}

void printStack(void)
{
	unsigned int   i;
	void         * stack[100];
	unsigned short frames;
	SYMBOL_INFO  * symbol;
	HANDLE         process;
	char		   buffer[100];
	char		   stackBuffer[2500];

	// MessageBoxA(NULL, "Debug", "Stack Trace", MB_OK);
	process = GetCurrentProcess();

	SymInitialize(process, NULL, TRUE);

	frames = CaptureStackBackTrace(0, 100, stack, NULL);
	symbol = (SYMBOL_INFO *)calloc(sizeof(SYMBOL_INFO) + 256 * sizeof(char), 1);
	symbol->MaxNameLen = 255;
	symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	ZeroMemory(buffer, sizeof(stackBuffer));

	for (i = 0; i < frames; i++)
	{
		SymFromAddr(process, (DWORD64)(stack[i]), 0, symbol);

		sprintf_s(buffer, "%i: %s - 0x%0X\r\n", frames - i - 1, symbol->Name, symbol->Address);
		strcat_s(stackBuffer, buffer);
	}
	//MessageBoxA(NULL, stackBuffer, "Stack Trace", MB_OK);
	//sprintf_s(logBuffer, "Stack Trace: %s", stackBuffer);
	unsigned long long after = GetTickCount();
	sprintf_s(logBuffer, "%llu", after);
	WriteLog(logBuffer);

	WriteLog(stackBuffer);
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

	WriteLog(TEXT("GetProcAddress_StackTrace:\n"));
	printStack();
	WriteLog(TEXT("n00b\n"));
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

	WriteLog(TEXT("LoadLibraryA_StackTrace:\n"));
	printStack();
	WriteLog(TEXT("n00b\n"));
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
	
	WriteLog(TEXT("LoadLibraryExA_StackTrace:\n"));
	printStack();
	WriteLog(TEXT("n00b\n"));
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
	
	WriteLog(TEXT("LoadLibraryExW_StackTrace:\n"));
	printStack();
	WriteLog(TEXT("n00b\n"));
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

	WriteLog(TEXT("LoadLibraryW_StackTrace:\n"));
	printStack();
	WriteLog(TEXT("n00b\n"));
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

	WriteLog(TEXT("VirtualAlloc_StackTrace:\n"));
	printStack();
	WriteLog(TEXT("n00b\n"));
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

	WriteLog(TEXT("VirtualAllocEx_StackTrace:\n"));
	printStack();
	WriteLog(TEXT("n00b\n"));
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
	// _PrintEnter("VirtualProtectEx(%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4);
	// MessageBoxA(NULL, "VirtualProtect hook!!", "Hook Message", MB_OK);
	
	WriteLog(TEXT("VirtualProtect_StackTrace:\n"));
	printStack();
	WriteLog(TEXT("n00b\n"));
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
	
	WriteLog(TEXT("VirtualProtectEx_StackTrace:\n"));
	printStack();
	WriteLog(TEXT("n00b\n"));
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
	LPTSTR szPathBuffer = NULL;
	
	if (DetourIsHelperProcess()) {
		return TRUE;
	}

	if (dwReason == DLL_PROCESS_ATTACH) {	
		EnableLogger();
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
		unsigned long long after = GetTickCount();
		sprintf_s(logBuffer, "Process close at %llu", after);
		WriteLog(logBuffer);
		//CloseHandle(hFile);
	}
	return TRUE;
}

extern "C" __declspec(dllexport) void dummy(void){
	return;
}