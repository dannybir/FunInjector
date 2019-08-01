#pragma once

#include <Windows.h>
#include <string_view>
#include <array>

#ifdef FUNINJECTOR_EXPORTS
#define FUNINJECTOR_EXPORTS __declspec(dllexport) 
#else
#define FUNINJECTOR_EXPORTS __declspec(dllimport) 
#endif

namespace FunInjector
{
	enum class EOperationStatus
	{
		SUCCESS,
		FAIL,
	};

	enum class EInjectionType : uint8_t
	{
		RemoteFunction = 0,
		CreateRemoteThread,
	};

	constexpr int MaxStringLength = 1024;
	struct InjectionParameters
	{
		// May use the handle or the process id
		DWORD ProcessId = 0;
		HANDLE ProcessHandle = nullptr;

		// This is mandatory
		std::array< wchar_t, MaxStringLength> DllPath;
		EInjectionType InjectionType;

		// Optional, depends on injection type
		std::array< char, MaxStringLength> TargetFunctionName;
		std::array< char, MaxStringLength> TargetModuleName;
	};

	void InjectUsingFunctionHook(const std::wstring_view DllPath,
		const std::string_view TargetFunctionName,
		const std::string_view TargetModuleName,
		DWORD ProcessId,
		HANDLE ProcessHandle = nullptr);
}

// Chooses injection method based on the given parameters
FUNINJECTOR_EXPORTS void InjectDllUsingStructure(FunInjector::InjectionParameters InjectParams);