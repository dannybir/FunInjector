// FunInjector.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include "FunInjectorAPI.h"
#include "FuncHookProcessInjector.h"

using namespace FunInjector;

namespace FunInjector
{
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
			Injector = 
				std::make_unique<FuncHookProcessInjector>(wil::shared_handle(ProcessHandle), DllPath.data(), TargetFunctionName.data(), TargetModuleName.data());
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


