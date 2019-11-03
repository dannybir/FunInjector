// FunInjector.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include "FunInjectorAPI.h"
#include "FuncHookProcessInjector.h"

using namespace FunInjector;

namespace FunInjector
{
	void InjectUsingFunctionHook(const std::wstring_view DllPath,
		const std::string_view TargetFunctionName,
		const std::string_view TargetModuleName,
		DWORD ProcessId,
		HANDLE ProcessHandle)
	{
		HANDLE_EXCEPTION_BEGIN;

		LOG_DEBUG << L"Trying to inject: " << DllPath << L", using a hook on: " << TargetModuleName << L"!" << TargetFunctionName;

		std::unique_ptr<FuncHookProcessInjector> Injector;
		if (ProcessHandle != nullptr && ProcessHandle != INVALID_HANDLE_VALUE)
		{
			Injector = 
				std::make_unique<FuncHookProcessInjector>(wil::shared_handle(ProcessHandle), DllPath.data(), TargetFunctionName.data(), TargetModuleName.data());
		}
		else if (ProcessId != 0)
		{
			Injector =
				std::make_unique<FuncHookProcessInjector>(ProcessId, DllPath.data(), TargetFunctionName.data(), TargetModuleName.data());
		}

		auto Status = Injector->PrepareForInjection();
		if (Status == EOperationStatus::FAIL)
		{
			LOG_ERROR << L"Failed to properly initialite the injector, would not continue with injection";
			return;
		}

		Status = Injector->InjectDll();
		if (Status == EOperationStatus::FAIL)
		{
			LOG_ERROR << L"Injecting: " << DllPath << L", has failed.";
		}

		HANDLE_EXCEPTION_END;
	}
}

void InjectDllUsingStructure(InjectionParameters InjectParams)
{
	switch (InjectParams.InjectionType)
	{
	case EInjectionType::RemoteFunction:
		InjectUsingFunctionHook(InjectParams.DllPath.data(), 
			InjectParams.TargetFunctionName.data(), InjectParams.TargetModuleName.data(), InjectParams.ProcessId, InjectParams.ProcessHandle);
		break;
	};
}


