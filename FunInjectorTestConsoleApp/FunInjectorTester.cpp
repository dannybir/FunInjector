
#include "../FunInjector/FunInjectorAPI.h"

// Command line options parser
#include <cxxopts.hpp>

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
#include <atomic>

#include <ProgressBar.hpp>

bool TryRunInjectTest(const std::filesystem::path& TesterBinariesPath)
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
	std::wstring InjectedEventName = L"InjectedEvent_" + std::to_wstring(ProcInfo.dwProcessId);
	InjectedEvent.create(wil::EventOptions::None, InjectedEventName.c_str());

	// Trigger the event so that injected dll can load
	ResumeThread(ProcInfo.hThread);

	// Wait for a maximum of 5 seconds, injected dll should be loaded and signal this event
	if (!InjectedEvent.wait(5000))
	{
		LOG_ERROR << L"Failed to inject TESTDLL.dll to the process, the injected event was not signaled";
		return false;
	}

	return true;
}

int main(int argc, char* argv[])
{
	try
	{
		static plog::ColorConsoleAppender<plog::TxtFormatter> ColorConsoleLogger;
		plog::init(plog::verbose, &ColorConsoleLogger);

		// set up command line options
		cxxopts::Options options(argv[0], " - FunInjectorTester command line options");

		options.add_options("Testing")
			("p,tpath", "Path to location of testing binaries", cxxopts::value<std::string>())
			("t,tries", "Amount of tries to do in a loop", cxxopts::value<int>())
			("m,threads", "Amount of threads to spread the test on", cxxopts::value<int>())
			("help", "Shows detailed information on all the commands");

		auto ParseResult = options.parse(argc, argv);
		if (ParseResult.count("help") > 0)
		{
			std::cout << options.help({ "Testing" }) << std::endl;
			return 0;
		}

		if (ParseResult.count("tpath") == 0)
		{
			LOG_ERROR << L"Did not pass the path to the binaries, cannot continue";
			return -2;
		}

		
		// This path is needed to see the location of the needed binaries, the test process and test dll
		std::string BinariesPathStr = ParseResult["tpath"].as< std::string >();
		auto BinariesPath = std::filesystem::path(BinariesPathStr);
		
		// Set up a text file logger for convinience
		auto TextLoggerPath = BinariesPath / "TesterLog.log";
		plog::RollingFileAppender<plog::TxtFormatter> FileLogger(TextLoggerPath.wstring().c_str(), 100000000, 100);
		plog::init(plog::debug, &FileLogger);

		//
		int TryAmount = 100;
		if (ParseResult.count("tries") > 0)
		{
			TryAmount = ParseResult["tries"].as<int>();
		}

		std::atomic<int> CurrentTry = 1;
		std::atomic<int> FailCounter = 0;
		std::mutex PrintMutex;

		auto TimeBeforeStart = std::chrono::high_resolution_clock::now();
		auto TesterFunction = [&](const auto& Path, const int IterationAmount)
		{
			for (;CurrentTry < IterationAmount; CurrentTry++)
			{
				if (!TryRunInjectTest(Path.wstring()))
				{
					FailCounter++;
				}

				std::lock_guard Guard(PrintMutex);
				auto CurrentTime = std::chrono::high_resolution_clock::now();
				auto PassedTimeInSeconds = std::chrono::duration_cast<std::chrono::seconds>(CurrentTime - TimeBeforeStart);

				using PrecisionMinutes = std::chrono::duration<float, std::ratio<60>>;
				std::cout << "**** Test " << CurrentTry << "/" << TryAmount << ", Fails: " << FailCounter << ", Passed Time: " 
					<< std::fixed << PrecisionMinutes( PassedTimeInSeconds ).count() << "min" << "\r";
			}
		};

		int DefaultThreadsAmount = 1;
		if (ParseResult.count("threads") > 0)
		{
			DefaultThreadsAmount = ParseResult["threads"].as<int>();
		}

		LOG_INFO << L"Starting tester function with path: " << BinariesPath.wstring() << L", and tries: " << TryAmount
			<< L", threads: " << DefaultThreadsAmount;

		std::vector< std::thread > TesterThreads;
		for (int Index = 0; Index < DefaultThreadsAmount; Index++)
		{
			std::thread TesterThread([=]()
			{
				TesterFunction(BinariesPath, TryAmount / DefaultThreadsAmount);
			});
			TesterThreads.push_back(std::move(TesterThread));
		}

		for (auto& Thread : TesterThreads)
		{
			Thread.join();
		}

		return 0;
	}
	catch (...)
	{
		std::cout << L"Exception occured while running tests, aborting";
		return -1;
	}

}

