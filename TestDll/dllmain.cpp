// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

// We would like this testdll to work in a native enviornment
// without the windows subsystem initialized
#include "TestDll.h"
#include <winternl.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	if (ul_reason_for_call != DLL_PROCESS_ATTACH)
	{
		return TRUE;
	}

	HANDLE EventHandle = nullptr;
	// ALL Access
	DWORD AccessMask = GENERIC_ALL;

	OBJECT_ATTRIBUTES EventAttributes = { 0 };
	UNICODE_STRING EventNameDesc;

#ifdef _WIN64
	wchar_t EventName[] = L"\\Sessions\\1\\BaseNamedObjects\\InjectedEvent64";
#else
	wchar_t EventName[] = L"\\Sessions\\1\\BaseNamedObjects\\InjectedEvent32";
#endif
	
	RtlInitUnicodeString(&EventNameDesc, EventName);

	InitializeObjectAttributes(&EventAttributes, &EventNameDesc, 0, nullptr, nullptr);

	NtOpenEvent(&EventHandle, AccessMask, &EventAttributes);
	NtSetEvent(EventHandle, nullptr);

    return TRUE;
}

