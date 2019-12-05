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
	enum class EOperationStatus : uint8_t
	{
		SUCCESS = 0,
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
		std::array< wchar_t, MaxStringLength> DllPath = { 0 };
		EInjectionType InjectionType;

		// Optional, depends on injection type
		std::array< char, MaxStringLength> TargetFunctionName = { 0 };
		std::array< char, MaxStringLength> TargetModuleName = { 0 };
	};

	EOperationStatus InjectUsingFunctionHook(const std::wstring_view DllPath,
		const std::string_view TargetFunctionName,
		const std::string_view TargetModuleName,
		HANDLE ProcessHandle,
		DWORD ProcessId = 0 ) noexcept;
}

// Chooses injection method based on the given parameters
// Can be used for multiple injection types, with dynamic or static linking
FUNINJECTOR_EXPORTS int InjectDllUsingStructure(FunInjector::InjectionParameters InjectParams);

// Will inject specifically using a remote function hook and assembly code injection method
FUNINJECTOR_EXPORTS int InjectWithFunctionHook(HANDLE ProcessHandle, 
	const wchar_t* DllPath, const char* TargetFunctionName, const char* TargetModuleName);