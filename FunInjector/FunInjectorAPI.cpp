// FunInjector.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include "FunInjectorAPI.h"

#include "ProcessInformationUtils.h"

namespace FunInjector
{
	// TODO: This is an example of a library function
	void InjectDll()
	{
		static plog::ColorConsoleAppender<plog::TxtFormatter> ColorConsoleLogger;
		plog::init(plog::debug, &ColorConsoleLogger);

		DWORD ProcId = 25908;
		auto ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, ProcId);

		ProcessInformationUtils ProcUtils(ProcessHandle, true);
		ProcUtils.GetFunctionAddress(L"CreateFileW");
		ProcUtils.GetModuleAddress(L"ntdll");
	}
}

