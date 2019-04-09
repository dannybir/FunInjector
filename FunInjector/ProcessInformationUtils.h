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

		// This function must be called before calling the module/function address query
		// It enumerates and retrieves information regarding the modules of the process
		EOperationStatus EnumerateProcessModules();

		// Refreshes the information stored in the symbol handler for the remote process modules
		// Use this if you know the module layout for the process changed since Enumerate was called
		EOperationStatus RefreshProcessModulesInfo();

		// Return the absolute address of a module in remote process memory
		// Enumerate/Refresh must be called before to make module has been enumerated
		DWORD64 GetModuleAddress(const std::wstring &ModuleName) const noexcept;

		// Return the aboslute address of the function in the process
		// Enumerate/Refresh must be called before
		DWORD64 GetFunctionAddress(const std::wstring_view FunctionName) const noexcept;

		// Read some bytes from the remote process into a buffer
		// Process handle must be opened with correct access rights or this will fail
		ByteBuffer ReadBufferFromProcess(DWORD64 ReadAddress, SIZE_T ReadSize) const noexcept;

		// Write a supplied buffer to a remote process at the given location
		// Process handle must be opened with correct access rights or this will fail
		EOperationStatus WriteBufferToProcess(const ByteBuffer& WriteBuffer, DWORD64 WriteAddress, SIZE_T WriteSize) const noexcept;

		// Find a free memory block that can hold FreeSize amount of room
		// Only looks for free pages, starts looking from ntdll.dll location going down in addresses
		// Will return the address of the start of the free page block
		DWORD64	FindFreeMemoryRegion(SIZE_T FreeMemorySize, bool ScanDown = true) const noexcept;

		// Allocates a block of memory to be ready for execution, returns the allocation base
		DWORD64 AllocateMemoryInProcessForExecution(DWORD64 MemoryAddress, SIZE_T AllocationSize) const noexcept;

	private:
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



