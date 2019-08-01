#pragma once

#include "pch.h"
#include <Psapi.h>
#include "ProcessMemoryInspector.h"
#include <functional>

namespace FunInjector::ProcessInspector
{
//
	enum class EModuleBitness : uint8_t
	{
		BIT_64,
		BIT_32,
		AUTOMATIC,
	};

	using ModuleMapKey = std::pair< std::string, EModuleBitness >;
	struct ModuleMapKeyHashFunctor
	{
		std::size_t operator()(ModuleMapKey const& Key) const noexcept
		{
			std::size_t Hash1 = std::hash<std::string>{}(Key.first);
			std::size_t Hash2 = std::hash<EModuleBitness>{}(Key.second);

			int Seed = 290791;

			// Implementation of boost::hash_combine to avoid collisions
			Seed ^= Hash1 + 0x9e3779b9 + (Seed << 6) + (Seed >> 2);
			Seed ^= Hash2 + 0x9e3779b9 + (Seed << 6) + (Seed >> 2);

			return Seed;
		}
	};

	// Function pointers definiton to functions in PSAPI.dll
	using FEnumProcessModulesExPtr = BOOL(__stdcall *)(HANDLE hProcess, HMODULE * lphModule, DWORD cb, LPDWORD lpcbNeeded, DWORD dwFilterFlag);
	using FGetModuleFileNameExWPtr = DWORD(__stdcall *)(HANDLE hProcess, HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
	using FGetModuleBaseNameWPtr = DWORD(__stdcall *)(HANDLE hProcess, HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
	using FGetModuleInformationPtr = BOOL(__stdcall *)(HANDLE hProcess, HMODULE hModule, LPMODULEINFO pmi, DWORD nSize);

	// Maximum amount of modules we can enumerate, should probably never pass this number for sane applications
	constexpr auto MAX_ENUMERATED_MODULE_NUM = 512;

	// Maximum string length for stack defined character arrays that are used here for simplicity and WinApi compatibility
	constexpr auto MAX_STRING_LEN = 2048;

	struct ModuleInformation
	{
		std::filesystem::path ModulePath;
		std::wstring		  ModuleName;
		DWORD64				  ModuleBase;
		DWORD64				  ModuleSize;

		EModuleBitness		  ModuleBitness;
		// Copy of the module loaded that is loaded into the remote process
		ByteBuffer			  ModuleBuffer; 
	};

	class ProcessModuleInspector
	{
	public:
		ProcessModuleInspector(wil::shared_handle ProcHandle);

		EOperationStatus LoadInformation() noexcept;

		// Return the absolute address of a module in remote process memory
		DWORD64 GetModuleAddress(const std::string &ModuleName, EModuleBitness ModBitness = EModuleBitness::AUTOMATIC) const noexcept;

		// Return the absolute size of the module in the remote process
		DWORD64 GetModuleSize(const std::string &ModuleName, EModuleBitness ModBitness = EModuleBitness::AUTOMATIC) const noexcept;

		ByteBuffer GetModuleBufferByName(const std::string& ModuleName, EModuleBitness ModBitness = EModuleBitness::AUTOMATIC) const noexcept;

		inline void AttachMemoryInspector(std::shared_ptr< ProcessMemoryInspector > MemInspector)
		{
			ProcMemInspector = MemInspector;
		}

		inline void AttachInfoInspector(std::shared_ptr< ProcessInformationInspector > InfoInspector)
		{
			ProcInfoInspector = InfoInspector;
		}

	private:
		void PrepareForModuleEnumeration() noexcept;

		const ModuleInformation& GetModuleByName(const std::string & ModuleName, EModuleBitness ModBitness) const;

		ByteBuffer GetModuleBuffer(DWORD64 ModuleBaseAddress, DWORD64 ModuleSize) const;
		bool IsModule64bitInternal(ByteBuffer& ModuleBuffer) const;

	private:
		// Function pointers to psapi.dll functions
		FEnumProcessModulesExPtr EnumProcessModulesExPtr = nullptr;
		FGetModuleFileNameExWPtr GetModuleFilenameExWPtr = nullptr;
		FGetModuleBaseNameWPtr	 GetModuleBaseNameWPtr = nullptr;
		FGetModuleInformationPtr GetModuleInformationPtr = nullptr;

		// An array of IMAGEHLP_MODULEW64 structures, which contain important information about each module
		std::unordered_map< ModuleMapKey, ModuleInformation, ModuleMapKeyHashFunctor > ProcessModuleMap;

		// Reference to a process handle, will enumerate handles from that process
		wil::shared_handle ProcessHandle;

		// For memory operations on the process
		std::shared_ptr< ProcessMemoryInspector> ProcMemInspector;

		// To receive information regarding the process containing the modules
		std::shared_ptr< ProcessInformationInspector> ProcInfoInspector;
	};
}



