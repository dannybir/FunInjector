#pragma once

#include "pch.h"


namespace FunInjector::ProcessUtils
{

	/*
	// TODO: Turn to singleton
	class ProcessInformationUtils
	{
	public:
		ProcessInformationUtils() = default;
		ProcessInformationUtils(HANDLE ProcHandle, bool Enumerate = true);
		~ProcessInformationUtils();

		// This function must be called before calling the module/function address query
		// It enumerates and retrieves information regarding the modules of the process
		EOperationStatus EnumerateProcessModules();

		// Refreshes the information stored in the symbol handler for the remote process modules
		// Use this if you know the module layout for the process changed since Enumerate was called
		EOperationStatus RefreshProcessModulesInfo();


		// Return the aboslute address of the function in the process
		// Enumerate/Refresh must be called before
		DWORD64 GetFunctionAddress(const std::wstring_view FunctionName) const noexcept;

		// If the process is 64bit, i.e the image of the executable is 64bit, this will return true
		bool	Is64BitProcess() const noexcept;

		// Will retrieve the process name if its not initialized yet,
		// subsequent calls will return the cached value
		std::wstring GetProcessName() const noexcept;

	private:
		EOperationStatus LoadSymbolForModule(const std::wstring_view ModulePath, const std::wstring_view ModuleName, DWORD64 ModuleBase, DWORD ModuleSize);

	private:




		// A *valid* handle for the process, must contain needed access rights
		HANDLE ProcessHandle = nullptr;

		// 
		std::wstring ProcessName;
	};
	*/
}



