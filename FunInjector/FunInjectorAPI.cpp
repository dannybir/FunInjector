// FunInjector.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include "FunInjectorAPI.h"
#include <tlhelp32.h>
#include "FuncHookProcessInjector.h"
#include "AssemblyCode.h"

namespace FunInjector
{
	using namespace Literals;
	// TODO: This is an example of a library function
	void InjectDll()
	{
		static plog::ColorConsoleAppender<plog::TxtFormatter> ColorConsoleLogger;
		plog::init(plog::debug, &ColorConsoleLogger);

		DWORD ProcessId = 0;

		PROCESSENTRY32 entry;
		entry.dwSize = sizeof(PROCESSENTRY32);
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

		if (Process32First(snapshot, &entry) == TRUE)
		{
			do
			{
				std::wstring ProcessName(entry.szExeFile);
				if (ProcessName == L"mspaint.exe")
				{
					ProcessId = entry.th32ProcessID;
					break;
				}

			} while (Process32Next(snapshot, &entry) == TRUE);
		}

		CloseHandle(snapshot);

		ErrorHandler::ExceptionHandlerInstance::GetInstance().SetHandlerName("InjectorExceptionHandler");
		ErrorHandler::ExceptionHandlerInstance::GetInstance().ToggleUseMessageBox(true);
		ErrorHandler::ExceptionHandlerInstance::GetInstance().TogglePringLog(true);

		FuncHookProcessInjector injector(ProcessId, L"C:\\Users\\DB\\Source\\Repos\\FunInjector\\FunInjector\\x64\\Debug\\TESTDLL.dll", "CreateFileW", L"kernelbase");
		injector.PrepareForInjection();
		injector.InjectDll();
	}

}

