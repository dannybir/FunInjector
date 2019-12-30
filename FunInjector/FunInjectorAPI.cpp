// FunInjector.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include "FunInjectorAPI.h"
#include "FuncHookProcessInjector.h"

using namespace FunInjector;

namespace FunInjector
{
	EOperationStatus DelegateToCLIInjector(
		const std::filesystem::path CLIInjectorPath,
		const std::wstring_view DllPath, 
		const std::string_view TargetFunctionName, 
		const std::string_view TargetModuleName, 
		DWORD ProcessId)
	{
		HANDLE_EXCEPTION_BEGIN;

		std::wostringstream CommandLineStream;
		CommandLineStream << CLIInjectorPath;
		CommandLineStream << L" -f";
		CommandLineStream << L" -d " << DllPath;
		CommandLineStream << L" -p " << ProcessId;
		CommandLineStream << L" -m " << std::wstring(TargetModuleName.begin(), TargetModuleName.end());
		CommandLineStream << L" -t " << std::wstring(TargetFunctionName.begin(), TargetFunctionName.end());

		auto CommandLine = CommandLineStream.str();

		// To use a 64bit host, we simply run the 64bit version of the CLI without a visible UI
		STARTUPINFOW StartupInfo{ 0 };
		StartupInfo.cb = sizeof(StartupInfo);

		PROCESS_INFORMATION ProcInfo{ 0 };
		auto Result = CreateProcessW(nullptr, CommandLine.data(), nullptr,
			nullptr, false, 0, 0, nullptr, &StartupInfo, &ProcInfo);

		if (!Result)
		{
			auto LastError = GetLastError();
			LOG_ERROR << L"Failed to launch the TestProcess.exe with errorcode: " << LastError;
			return EOperationStatus::FAIL;
		}

		// Make sure handles are closed
		wil::unique_handle ProcessHandle(ProcInfo.hProcess);
		wil::unique_handle ThreadHandle(ProcInfo.hThread);

		// Wait for 10 seconds maximum
		constexpr auto WaitForCompletionTime = 10000;
		auto WaitResult = WaitForSingleObject(ProcessHandle.get(), WaitForCompletionTime);
		if (WaitResult != WAIT_OBJECT_0)
		{
			LOG_ERROR << L"Failed while waiting for the CLI to finish with the injection, something went wrong"
				<< L",will report a failed injection";
			return EOperationStatus::FAIL;
		}

		LOG_DEBUG << L"Getting an exit code from the injector CLI process";
		DWORD ExitCode = 0;
		if (!GetExitCodeProcess(ProcessHandle.get(), &ExitCode))
		{
			LOG_ERROR << L"Failed to get an exit code from the injector CLI process, cannot know if it was succeseful"
				<< L", will fail the injection";
			return EOperationStatus::FAIL;
		}

		if (ExitCode != 0)
		{
			LOG_ERROR << L"CLI injector returned an exit code: " << ExitCode << L", will fail the injection";
			return EOperationStatus::FAIL;
		}
		
		LOG_DEBUG << L"Injection using the CLI injector was succuseful!";
		return EOperationStatus::SUCCESS;

		HANDLE_EXCEPTION_END_RET(EOperationStatus::FAIL);
	}

	EOperationStatus InjectUsingFunctionHook(const std::wstring_view DllPath,
											 const std::string_view TargetFunctionName,
											 const std::string_view TargetModuleName,
											 HANDLE ProcessHandle,
											 DWORD ProcessId) noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		LOG_DEBUG << L"Trying to inject: " << DllPath << L", using a hook on: " << TargetModuleName << L"!" << TargetFunctionName;

		// Use the handle if it fine
		std::unique_ptr<FuncHookProcessInjector> Injector;
		if (ProcessHandle != nullptr && ProcessHandle != INVALID_HANDLE_VALUE)
		{
			Injector = std::make_unique<FuncHookProcessInjector>(wil::shared_handle(ProcessHandle), DllPath.data(), TargetFunctionName.data(), TargetModuleName.data());
		}
		else if (ProcessId != 0)
		{
			// Otherwise use the process id, a handle will be created later
			Injector =
				std::make_unique<FuncHookProcessInjector>(ProcessId, DllPath.data(), TargetFunctionName.data(), TargetModuleName.data());
		}

		auto Status = Injector->PrepareForInjection();
		if (Status == EOperationStatus::FAIL)
		{
			LOG_ERROR << L"Failed to properly initialite the injector, would not continue with injection";
			return Status;
		}
		else if (Status == EOperationStatus::USE_64_HOST)
		{
			// 
			LOG_ERROR << L"Not supported";
			return EOperationStatus::FAIL;
		}

		Status = Injector->InjectDll();
		if (Status == EOperationStatus::FAIL)
		{
			LOG_ERROR << L"Injecting: " << DllPath << L", has failed.";
		}

		return Status;

		HANDLE_EXCEPTION_END_RET(EOperationStatus::FAIL);
	}
}

int InjectDllUsingStructure(InjectionParameters InjectParams)
{
	switch (InjectParams.InjectionType)
	{
	case EInjectionType::RemoteFunction:
		return std::underlying_type_t<EOperationStatus>(
			FunInjector::InjectUsingFunctionHook(InjectParams.DllPath.data(), InjectParams.TargetFunctionName.data(),
				InjectParams.TargetModuleName.data(), InjectParams.ProcessHandle, InjectParams.ProcessId));
		break;

		// TODO: More injection methods
	};

	return -1;
}

FUNINJECTOR_EXPORTS int InjectWithFunctionHook(HANDLE ProcessHandle, 
	const wchar_t * DllPath, const char * TargetFunctionName, const char * TargetModuleName)
{
	HANDLE_EXCEPTION_BEGIN;

	if (DllPath == nullptr || TargetFunctionName == nullptr || TargetModuleName == nullptr
		|| ProcessHandle == INVALID_HANDLE_VALUE || ProcessHandle == nullptr)
	{
		LOG_ERROR << L"One of the parameters passed is null, cannot continue!";
		return -1;
	}

	LOG_DEBUG << L"Will now try to inject: " << DllPath << L", using the following victim function: " << TargetModuleName
		<< L"!" << TargetFunctionName;

	return std::underlying_type_t<EOperationStatus>( 
		FunInjector::InjectUsingFunctionHook(DllPath, TargetFunctionName, TargetModuleName, ProcessHandle, 0 ));

	HANDLE_EXCEPTION_END;
	return -2;
}


