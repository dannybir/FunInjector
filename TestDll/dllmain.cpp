// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

// We would like this testdll to work in a native enviornment
// without the windows subsystem initialized
#include "TestDll.h"
#include <winternl.h>


void NullMemory(void* MemPtr, int size)
{
	unsigned char* Ptr = reinterpret_cast<unsigned char*>(MemPtr);
	for (int i = 0; i < size; i++)
	{
		*Ptr = (unsigned char)0;
		Ptr++;
	}
}

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
	

	PROCESS_BASIC_INFORMATION BasicProcessInfo = { 0 };
	NtQueryInformationProcess((HANDLE)-1, ProcessBasicInformation, &BasicProcessInfo, sizeof(BasicProcessInfo), nullptr);

	WCHAR EventName[MAX_PATH];
	NullMemory(EventName, sizeof(wchar_t)* MAX_PATH);

	UNICODE_STRING EventNameU;
	EventNameU.MaximumLength = MAX_PATH;
	EventNameU.Buffer = EventName;
	EventNameU.Length = 0;

	UNICODE_STRING EventNameBase;
	RtlInitUnicodeString(&EventNameBase, L"\\Sessions\\1\\BaseNamedObjects\\InjectedEvent_");
	RtlAppendUnicodeStringToString(&EventNameU, &EventNameBase);

	WCHAR ProcessIdStr[20];
	NullMemory(ProcessIdStr, sizeof(wchar_t) * 20);

	UNICODE_STRING ProcessIdString;
	ProcessIdString.Buffer = ProcessIdStr;
	ProcessIdString.MaximumLength = 20;

	RtlIntegerToUnicodeString(BasicProcessInfo.UniqueProcessId, 10, &ProcessIdString);

	// Append the process id to the injected event name
	RtlAppendUnicodeStringToString(&EventNameU, &ProcessIdString);


	InitializeObjectAttributes(&EventAttributes, &EventNameU, 0, nullptr, nullptr);

	NtOpenEvent(&EventHandle, AccessMask, &EventAttributes);
	NtSetEvent(EventHandle, nullptr);

    return TRUE;
}

