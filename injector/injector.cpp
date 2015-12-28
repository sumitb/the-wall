// DetoursInjector.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <detours.h>

#pragma comment(lib, "detours.lib")
#define MAX_COMBINED 8192

LPTSTR GetArguments(void)
{
	LPWSTR *szArglist = NULL;
	int nArgs;
	LPWSTR  wbuf = NULL;

	wbuf = new WCHAR[MAX_COMBINED];

	if (wbuf == NULL)
		return NULL;

	memset(wbuf, 0, MAX_COMBINED*sizeof(WCHAR));
	szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
	if (NULL == szArglist)
	{
		return NULL;
	}
	else {
		for (int i = 2; i<nArgs; i++) {
			wcscat_s(wbuf, MAX_COMBINED, szArglist[i]);
			wcscat_s(wbuf, MAX_COMBINED, L" ");
		}
	}
	LocalFree(szArglist);

#ifdef _UNICODE
	return wbuf;
#else
	LPSTR abuf = new CHAR[MAX_COMBINED];

	if (abuf == NULL)
		return NULL;

	memset(abuf, 0, MAX_COMBINED);
	WideCharToMultiByte(CP_ACP, 0, wbuf, -1, abuf, MAX_COMBINED, NULL, NULL);

	delete[] wbuf;
	return abuf;
#endif
}

bool Inject(DWORD pId, char *dllName)
{
	HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, false, pId);
	if (h)
	{
		LPVOID LoadLibAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
		LPVOID dereercomp = VirtualAllocEx(h, NULL, strlen(dllName), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		WriteProcessMemory(h, dereercomp, dllName, strlen(dllName), NULL);
		HANDLE asdc = CreateRemoteThread(h, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddr, dereercomp, 0, NULL);
		WaitForSingleObject(asdc, INFINITE);
		VirtualFreeEx(h, dereercomp, strlen(dllName), MEM_RELEASE);
		CloseHandle(asdc);
		CloseHandle(h);
		return true;
	}
	return false;
}

int _tmain(int argc, _TCHAR* argv[])
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	LPTSTR szCmdLine = NULL;
	CHAR   szDllName[MAX_PATH];
	CHAR   szDetouredDll[MAX_PATH];
	BOOL   bStatus;
	wchar_t*  pEnd;
	DWORD  pid;
	pid = wcstol(argv[1], &pEnd, 10);
	// pid = atof((const char*)argv[1]);
	/* Dll injection in a running process with pid */
	Inject(pid, "C:\\Users\\sbindal\\vs2013\\Projects\\cse523\\Release\\detoured.dll");

	/*if (argc < 3)
	{
		_tprintf(_T("\nUsage: %s <DLL> <PROCESS [ARGS]>\n"), argv[0]);
		return -1;
	}

	if ((szCmdLine = GetArguments()) == NULL)
	{
		_tprintf(_T("Failed to parse command line!\n"));
		return -1;
	}

	GetCurrentDirectoryA(MAX_PATH, szDetouredDll);
	GetCurrentDirectoryA(MAX_PATH, szDllName);

	strcat_s(szDetouredDll, MAX_PATH, "\\detoured.dll");
	strcat_s(szDllName, MAX_PATH, "\\");

#ifdef _UNICODE
	WideCharToMultiByte(CP_ACP, 0, argv[1], -1,
		szDllName + strlen(szDllName),
		MAX_PATH, NULL, NULL);
#else
	strcat_s(szDllName, MAX_PATH, argv[1]);
#endif

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);

	bStatus = DetourCreateProcessWithDll(
		NULL,      // application name 
		szCmdLine, // full command line + arguments 
		NULL,      // process attributes
		NULL,      // thread attributes
		FALSE,     // inherit handles
		0,         // creation flags
		NULL,      // environment
		NULL,      // current directory
		&si,       // startup info
		&pi,       // process info
		szDllName, // path to dll to inject
		NULL);     // use standard CreateProcess API 

	if (bStatus) {
		_tprintf(_T("Created process PID %d!\n"), pi.dwProcessId);
	}
	else {
		_tprintf(_T("Error creating process!\n"));
	}*/

	return 0;
}

