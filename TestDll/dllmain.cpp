// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <wil/resource.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	if (ul_reason_for_call != DLL_PROCESS_ATTACH)
	{
		return TRUE;
	}

	wil::unique_event_nothrow InjectedEvent;
	if (FAILED(InjectedEvent.open(L"InjectedEvent")))
	{
		return FALSE;
	}

	InjectedEvent.SetEvent();
    
    return TRUE;
}

