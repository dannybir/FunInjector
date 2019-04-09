#pragma once

#include "pch.h"
#include <Psapi.h>

namespace FunInjector
{
	// Function pointers definiton to functions in PSAPI.dll
	using FEnumProcessModulesExPtr = BOOL(__stdcall *)(HANDLE hProcess, HMODULE * lphModule, DWORD cb, LPDWORD lpcbNeeded, DWORD dwFilterFlag);
	using FGetModuleFileNameExWPtr = DWORD(__stdcall *)(HANDLE hProcess, HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
	using FGetModuleBaseNameWPtr = DWORD(__stdcall *)(HANDLE hProcess, HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
	using FGetModuleInformationPtr = BOOL(__stdcall *)(HANDLE hProcess, HMODULE hModule, LPMODULEINFO pmi, DWORD nSize);

	// Maximum amount of modules we can enumerate, should probably never pass this number for sane applications
	constexpr auto MAX_ENUMERATED_MODULE_NUM = 512;

	// Maximum string length for stack defined character arrays that are used here for simplicity and WinApi compatibility
	constexpr auto MAX_STRING_LEN = 2048;

	// All memory read or write function should return a byte buffer, which is just a std::vector of byte sized data type
	using ByteBuffer = std::vector< unsigned char >;

	// TODO: Turn to singleton
	class ProcessInformationUtils
	{
	public:
		ProcessInformationUtils(HANDLE ProcHandle, bool Enumerate = true);
		~ProcessInformationUtils();

		// Refreshes the information stored in the symbol handler for the remote process modules
		// Use this if you know the module layout for the process changed since Enumerate was called
		EOperationStatus RefreshProcessModulesInfo() const;

		// Return the absolute address of a module in remote process memory
		// Enumerate/Refresh must be called before to make module has been enumerated
		DWORD64 GetModuleAddress(const std::wstring &ModuleName) const;

		// Return the aboslute address of the function in the process
		// Enumerate/Refresh must be called before
		DWORD64 GetFunctionAddress(const std::wstring_view FunctionName) const;

		// Read some bytes from the remote process into a buffer
		// Process handle must be opened with correct access rights or this will fail
		ByteBuffer ReadBufferFromProcess(DWORD64 ReadAddress, SIZE_T ReadSize) const;
	private:
		EOperationStatus EnumerateProcessModules();
		EOperationStatus PrepareForModuleEnumeration();
		EOperationStatus LoadSymbolsForProcessModules();
		EOperationStatus LoadSymbolForModule(const std::wstring_view ModulePath, const std::wstring_view ModuleName, DWORD64 ModuleBase, DWORD ModuleSize);

	private:
		// Function pointers to psapi.dll functions
		FEnumProcessModulesExPtr EnumProcessModulesExPtr = nullptr;
		FGetModuleFileNameExWPtr GetModuleFilenameExWPtr = nullptr;
		FGetModuleBaseNameWPtr GetModuleBaseNameWPtr = nullptr;
		FGetModuleInformationPtr GetModuleInformationPtr = nullptr;

		// An array of IMAGEHLP_MODULEW64 structures, which contain important information about each module
		std::unordered_map< std::wstring, IMAGEHLP_MODULEW64 > ProcessModuleMap;

		// A *valid* handle for the process, must contain needed access rights
		HANDLE ProcessHandle;
	};
}



