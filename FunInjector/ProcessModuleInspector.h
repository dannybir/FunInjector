#pragma once

#include "pch.h"
#include "ProcessMemoryInspector.h"
#include <Psapi.h>
#include <functional>

namespace FunInjector::ProcessInspector
{
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

	// Function pointers definiton to functions in PSAPI.dll
	using FEnumProcessModulesExPtr = BOOL(__stdcall *)(HANDLE hProcess, HMODULE * lphModule, DWORD cb, LPDWORD lpcbNeeded, DWORD dwFilterFlag);
	using FGetModuleFileNameExWPtr = DWORD(__stdcall *)(HANDLE hProcess, HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
	using FGetModuleBaseNameWPtr = DWORD(__stdcall *)(HANDLE hProcess, HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
	using FGetModuleInformationPtr = BOOL(__stdcall *)(HANDLE hProcess, HMODULE hModule, LPMODULEINFO pmi, DWORD nSize);

	// Maximum amount of modules we can enumerate, should probably never pass this number for sane applications
	constexpr auto MAX_ENUMERATED_MODULE_NUM = 512;

	// Maximum string length for stack defined character arrays that are used here for simplicity and WinApi compatibility
	constexpr auto MAX_STRING_LEN = 2048;

	class ProcessModuleInspector
	{
	public:
		ProcessModuleInspector(wil::shared_handle ProcHandle);

		EOperationStatus LoadInformation(const std::wstring& SpecificModuleName = L"") noexcept;

		// Return the absolute address of a module in remote process memory
		DWORD64 GetModuleAddress(const std::string &ModuleName, 
			EModuleBitness ModBitness = EModuleBitness::AUTOMATIC) const noexcept;

		// Return the absolute size of the module in the remote process
		DWORD64 GetModuleSize(const std::string &ModuleName, 
			EModuleBitness ModBitness = EModuleBitness::AUTOMATIC) const noexcept;

		// Retrieves a buffer containing the module image, if exists
		ByteBuffer GetModuleBufferByName(const std::string& ModuleName, 
			EModuleBitness ModBitness = EModuleBitness::AUTOMATIC) const noexcept;

		inline void AttachMemoryInspector(std::shared_ptr< ProcessMemoryInspector > MemInspector)
		{
			ProcMemInspector = MemInspector;
		}

		inline void AttachInfoInspector(std::shared_ptr< ProcessInformationInspector > InfoInspector)
		{
			ProcInfoInspector = InfoInspector;
		}

	private:
		// Loads up the functions for enumeration with GetProcAddress
		void PrepareForModuleEnumeration();

		// Tries to return a reference to a module information structure
		// Throws an exception if it fails
		const ModuleInformation& GetModuleByName(const std::string & ModuleName, EModuleBitness ModBitness) const;

		// Will retrieve all needed information and add a ModuleInfo object to the map
		void ProcessNewModule(const DWORD64 ModuleBase, const DWORD ModuleSize);

		// Loads module information using the regular method
		// of module enumeration
		//void LoadInformationInternal(const std::wstring& SpecificModuleName = L"");

		// Loads module information using iteration on the LDR that
		// is specified in the target process PEB
		// This should only be used for 64bit processes
		// Unused, kept for future reference
		//void LoadInformationInternalWithPeb64(const std::wstring& SpecificModuleName = L"");

		/*
		
		// Helper function, easily read a certain structure from the target process memory
		template <typename StructType>
		bool TryGetStructFromRemoteProcess(DWORD64 RemoteStructPtr, StructType* Struct)
		{
			auto Buffer = ProcMemInspector->ReadBufferFromProcess(RemoteStructPtr, sizeof(StructType));
			if (Buffer.size() == 0)
			{
				LOG_ERROR << L"Failed to retrieve the buffer of structure: " << typeid(StructType).name();
				return false;
			}

			if (Struct == nullptr)
			{
				return false;
			}

			std::memcpy(Struct, &Buffer[0], sizeof(StructType));
			return true;
		}
		*/
	private:
		/*
		// Function pointers to psapi.dll functions
		FEnumProcessModulesExPtr EnumProcessModulesExPtr = nullptr;
		FGetModuleFileNameExWPtr GetModuleFilenameExWPtr = nullptr;
		FGetModuleBaseNameWPtr	 GetModuleBaseNameWPtr = nullptr;
		FGetModuleInformationPtr GetModuleInformationPtr = nullptr;

		// Address of the remote process PEB structure
		// Will be found by the Prepare function
		DWORD64 PebAddress = 0;
		*/

		// An array of ModuleInformation structures, which contain important information about each module
		// The key is a combination of the module name and its bitness
		std::unordered_map< ModuleMapKey, ModuleInformation, ModuleMapKeyHashFunctor > ProcessModuleMap;

		// Reference to a process handle, will enumerate handles from that process
		wil::shared_handle ProcessHandle;

		// For memory operations on the process
		std::shared_ptr< ProcessMemoryInspector> ProcMemInspector;

		// To receive information regarding the process containing the modules
		std::shared_ptr< ProcessInformationInspector> ProcInfoInspector;
	};
}



