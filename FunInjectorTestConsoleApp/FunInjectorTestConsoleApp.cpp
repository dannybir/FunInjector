// FunInjectorTestConsoleApp.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


#include "../FunInjector/FunInjectorAPI.h"
#include <Windows.h>

#include <wil/resource.h>
#include <thread>
#include <chrono>
using namespace std::chrono_literals;

#include <filesystem>

// Logger
#include <plog/Log.h>
#include <plog/Appenders/ColorConsoleAppender.h>

#include <future>

bool TryRunInjectTest(const std::filesystem::path& TesterBinariesPath, bool Is64BitTargetDll)
{
	// Default location:
	auto TesterBinaryLocation = TesterBinariesPath;
	auto TestProcessLocation = TesterBinaryLocation / "TestProcess.exe";
	auto TestDllLocation = TesterBinaryLocation / "TESTDLL.DLL";

	// Check if test binaries exist in said locations
	std::error_code FilesystemError;
	if (!std::filesystem::exists(TestProcessLocation, FilesystemError))
	{
		LOG_ERROR << L"Unable to find binary file: " << TestProcessLocation.wstring();
		return false;
	}

	if (!std::filesystem::exists(TestDllLocation, FilesystemError))
	{
		LOG_ERROR << L"Unable to find binary file: " << TestDllLocation.wstring();
		return false;
	}

	// After mapping is done, launch the test process
	STARTUPINFOW StartupInfo{ 0 };
	StartupInfo.cb = sizeof(StartupInfo);

	PROCESS_INFORMATION ProcInfo{ 0 };
	auto Result = CreateProcessW(TestProcessLocation.wstring().c_str(), nullptr, nullptr, 
		nullptr, false, CREATE_SUSPENDED, 0, nullptr, &StartupInfo, &ProcInfo);

	if (!Result)
	{
		auto LastError = GetLastError();
		LOG_ERROR << L"Failed to launch the TestProcess.exe with errorcode: " << LastError;
		return false;
	}

	// Give the process a second to start
	std::this_thread::sleep_for(1s);

	// After test process is launched, inject it with the test dll
	FunInjector::InjectionParameters Params;

	auto DllPath = std::wstring(TestDllLocation.wstring().c_str());
	std::copy_n(DllPath.begin(), DllPath.size(), Params.DllPath.begin());

	auto FunctionName = std::string("RtlInitializeHandleTable");
	std::copy_n(FunctionName.begin(), FunctionName.size(), Params.TargetFunctionName.begin());

	auto ModuleName = std::string("ntdll.dll");
	std::copy_n(ModuleName.begin(), ModuleName.size(), Params.TargetModuleName.begin());

	wil::shared_handle ProcessHandle(ProcInfo.hProcess);
	wil::shared_handle ThreadHandle(ProcInfo.hThread);

	Params.ProcessHandle = ProcInfo.hProcess;
	Params.InjectionType = FunInjector::EInjectionType::RemoteFunction;

	if (InjectDllUsingStructure(Params) != 0)
	{
		LOG_ERROR << L"Failed to inject to TestProcess.exe";
		return false;
	}

	// Create the trigger event that created processes will wait on
	wil::unique_event_nothrow InjectedEvent;
	std::wstring InjectedEventName = (Is64BitTargetDll) ? L"InjectedEvent64" : L"InjectedEvent32";
	InjectedEvent.create(wil::EventOptions::None, InjectedEventName.c_str());

	// Trigger the event so that injected dll can load
	ResumeThread(ProcInfo.hThread);

	// Wait for a maximum of 5 seconds, injected dll should be loaded and signal this event
	if (!InjectedEvent.wait(5000))
	{
		LOG_ERROR << L"Failed to inject TESTDLL.dll to the process, the injected event was not signaled";
		return false;
	}
	
	LOG_INFO << L"Injection successeful!";
	return true;
}

int wmain(int argc, wchar_t *argv[], wchar_t *envp[])
{
	plog::RollingFileAppender<plog::TxtFormatter> FileLogger(L"D:/Tester/TesterLog.log", 100000000, 100);
	plog::init(plog::debug, &FileLogger);

	static plog::ColorConsoleAppender<plog::TxtFormatter> ColorConsoleLogger;
	plog::init(plog::verbose, &ColorConsoleLogger);

	/*
	LOG_INFO << L"Starting 32bit injection tester!";
	
	int FailCounter = 0;
	
	for (int i = 0; i < 10; i++)
	{
		LOG_INFO << "******************************";
		LOG_INFO << "Running test number: " << i;
		if (!TryRunInjectTest(L"D:/Tester/x86", false))
		{
			FailCounter++;
		}
		LOG_INFO << "Concluded test number: " << i;
		LOG_INFO << "******************************";
	}

	LOG_INFO << L"Tester has concluded with: " << FailCounter << L", fails out of 500 tries for 32bit process";
	LOG_INFO << L"Starting 64bit injection tester!";
	*/
	int FailCounter = 0;
	for (int i = 0; i < 10; i++)
	{
		LOG_INFO << "******************************";
		LOG_INFO << "Running test number: " << i;
		if (!TryRunInjectTest(L"D:/Tester/x64", true))
		{
			FailCounter++;
		}
		LOG_INFO << "Concluded test number: " << i;
		LOG_INFO << "******************************";
	}

	LOG_INFO << L"Tester has concluded with: " << FailCounter << L", fails out of 500 tries for 64bit process";
	return 0;
}

