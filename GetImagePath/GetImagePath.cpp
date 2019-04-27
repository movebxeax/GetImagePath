#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>

#pragma comment(lib, "psapi.lib")

#pragma warning(disable:4996)

#define STATUS_INFO_LENGTH_MISMATCH            ((NTSTATUS)0xC0000004L)
#define STATUS_INVALID_CID                        ((NTSTATUS)0xC000000BL)
#define SYSTEM_PROCESS_ID_INFORMATION         (SYSTEM_INFORMATION_CLASS)88

typedef NTSTATUS(WINAPI *PNtQuerySystemInformation) (SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

typedef struct _SYSTEM_PROCESS_IMAGE_NAME_INFORMATION
{
	HANDLE ProcessId;
	UNICODE_STRING ImageName;
} SYSTEM_PROCESS_IMAGE_NAME_INFORMATION, *PSYSTEM_PROCESS_IMAGE_NAME_INFORMATION;

bool isLowerVista()
{
	DWORD dwVersion = 0;
	DWORD dwMajorVersion = 0;

	dwVersion = GetVersion();

	dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));

	if (dwMajorVersion <= 5)
		return true;
	else
		return false;
}

int main()
{
	DWORD dwPID = 0;
	NTSTATUS status;
	WCHAR *szBuffer;
	SYSTEM_PROCESS_IMAGE_NAME_INFORMATION ProcessInfo;
	HMODULE hNtdll;
	PNtQuerySystemInformation _NtQuerySystemInformation;

	wprintf(L"Plz query data with this pid! - ");
	wscanf(L"%d", &dwPID);

	if(isLowerVista())
	{
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, NULL, dwPID);

		if (hProcess == NULL)
		{
			wprintf(L"Error while opening the process with pid [%d]\n", dwPID);
			return -1;
		}

		szBuffer = (WCHAR *)malloc(sizeof(WCHAR) * MAX_PATH);

		int retval = GetModuleFileNameEx(hProcess, NULL, szBuffer, sizeof(WCHAR)*MAX_PATH);

		if (!retval)
		{
			wprintf(L"Error while querying image path\nError code %xh\n",GetLastError());
		}
		else
		{
			wprintf(L"Process Image Path is %ls\n", szBuffer);
		}

		CloseHandle(hProcess);
	}

	else
	{
		hNtdll = GetModuleHandleW(L"ntdll.dll");
		if (!hNtdll)
		{
			wprintf(L"GetModuleHandle Error with code %Xh\n", GetLastError());
			return -1;
		}

		_NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
		if (!_NtQuerySystemInformation)
		{
			wprintf(L"GetProcAddress Error with code %Xh\n", GetLastError());
			return -1;
		}

		szBuffer = (WCHAR*)malloc(MAX_PATH * sizeof(WCHAR));
		ProcessInfo.ProcessId = (HANDLE)dwPID;
		ProcessInfo.ImageName.Length = 0;
		ProcessInfo.ImageName.MaximumLength = (USHORT)MAX_PATH * sizeof(WCHAR);
		ProcessInfo.ImageName.Buffer = szBuffer;

		status = _NtQuerySystemInformation(SYSTEM_PROCESS_ID_INFORMATION, &ProcessInfo, sizeof(ProcessInfo), NULL);

		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			free(szBuffer);
			szBuffer = (WCHAR*)malloc(ProcessInfo.ImageName.MaximumLength);
			ProcessInfo.ImageName.Buffer = szBuffer;
			status = _NtQuerySystemInformation(SYSTEM_PROCESS_ID_INFORMATION, &ProcessInfo, sizeof(ProcessInfo), NULL);
		}

		if (NT_SUCCESS(status))
		{
			wprintf(L"ProcessInfo.ImageName.Length = %d\n", ProcessInfo.ImageName.Length);
			wprintf(L"ProcessInfo.ImageName.Buffer = %.*s\n", ProcessInfo.ImageName.Length / 2, ProcessInfo.ImageName.Buffer);
		}
		else
		{
			if (status == STATUS_INVALID_CID)
			{
				wprintf(L"There's no process with given pid [%d]\n", dwPID);
			}
			else
			{
				wprintf(L"Something happened while querying process info. Plz try later\nError Code %Xh", GetLastError());
			}
		}		
	}

	free(szBuffer);

	return 0;
}