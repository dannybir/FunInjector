#include "stdafx.h"
#include "CppUnitTest.h"
#include <Windows.h>

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace FunInjectorTester
{		

	void RunTestConsoleApp(bool is64Bit)
	{
		// After mapping is done, launch the test process
		STARTUPINFOW StartupInfo{ 0 };
		StartupInfo.cb = sizeof(StartupInfo);

		PROCESS_INFORMATION ProcInfo{ 0 };

		WCHAR CommandLine[] = L"D:/Tester/x64";

		auto Result = CreateProcessW(L"D:/Tester/FunInjectorTestConsoleApp.exe", CommandLine, 
			nullptr, nullptr, false, 0, 0, nullptr, &StartupInfo, &ProcInfo);

		// If process was not created, fail here
		Assert::AreEqual((BOOL)1, Result, L"Failed to open process: FunInjectorTestConsoleApp.exe");

		// Wait for the process to exit
			  // Successfully created the process.  Wait for it to finish.
		WaitForSingleObject(ProcInfo.hProcess, INFINITE);

		// Get the exit code.
		DWORD ExitCode = 0;
		Result = GetExitCodeProcess(ProcInfo.hProcess, &ExitCode);

		// Close the handles.
		CloseHandle(ProcInfo.hProcess);
		CloseHandle(ProcInfo.hThread);

		std::wstring Message = L"Injector test has ended with code: " + std::to_wstring(ExitCode);
		Assert::AreEqual((DWORD)0, ExitCode, Message.c_str());		
	}

	TEST_CLASS(InjectionTester)
	{
	public:
		
		TEST_METHOD(Inject64Bit)
		{
			// TODO: Your test code here
			RunTestConsoleApp(true);
		}

	};
}