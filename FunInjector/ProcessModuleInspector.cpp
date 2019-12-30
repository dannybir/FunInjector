#include "pch.h"
#include "ProcessModuleInspector.h"

// For std::to_wllower
#include <cwctype>
#include <cctype>

#include <Windows.h>
#include "NtDeclarations.h"

#include <TlHelp32.h>

namespace FunInjector::ProcessInspector
{


	ProcessModuleInspector::ProcessModuleInspector(wil::shared_handle ProcHandle) : ProcessHandle(ProcHandle)
	{
	}

	EOperationStatus ProcessModuleInspector::LoadInformation(const std::wstring & SpecificModuleName) noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		auto ImageBaseAndSize = ProcMemInspector->FindClosestImageBaseAndSize(0, false);
		while (ImageBaseAndSize)
		{
			// Process this image
			auto Base = ImageBaseAndSize.value().first;
			auto Size = ImageBaseAndSize.value().second;

			// Process new module may throw an exception on failure, but we still want to continue scanning
			HANDLE_EXCEPTION_BEGIN;
			ProcessNewModule(Base, Size);
			HANDLE_EXCEPTION_END;

			ImageBaseAndSize = ProcMemInspector->FindClosestImageBaseAndSize(Base + Size, false);
		}
		
		LOG_DEBUG << L"Succesefully finished loading module information from the target process";
		return EOperationStatus::SUCCESS;

		HANDLE_EXCEPTION_END_RET(EOperationStatus::FAIL);
	}

	DWORD64 ProcessModuleInspector::GetModuleAddress(const std::string & ModuleName, EModuleBitness ModBitness) const noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		auto ModuleInfo = GetModuleByName(ModuleName, ModBitness);
		return ModuleInfo.ModuleBase;

		HANDLE_EXCEPTION_END_RET(0);
	}

	DWORD64 ProcessModuleInspector::GetModuleSize(const std::string & ModuleName, EModuleBitness ModBitness) const noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		auto ModuleInfo = GetModuleByName(ModuleName, ModBitness);
		return ModuleInfo.ModuleSize;

		HANDLE_EXCEPTION_END_RET(0);
	}

	ByteBuffer ProcessModuleInspector::GetModuleBufferByName(const std::string & ModuleName, EModuleBitness ModBitness) const noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		auto ModuleInfo = GetModuleByName(ModuleName, ModBitness);
		if (ModuleInfo.ModuleBuffer.size() > 0)
		{
			return ModuleInfo.ModuleBuffer;
		}

		// May return an empty buffer if something goes wrong
		return ProcMemInspector->ReadBufferFromProcess(ModuleInfo.ModuleBase, static_cast<size_t>(ModuleInfo.ModuleSize));

		HANDLE_EXCEPTION_END_RET(ByteBuffer());
	}
	/*
	void ProcessModuleInspector::PrepareForModuleEnumeration()
	{
		// Pay attention here, we must use PEB based module enumeration when in Wow64 mode
		// This is because when we are 32bit process, we cannot enumerate modules from a 64bit process
		// using the regular functions, that will fail.
		if (ProcInfoInspector->ShouldUseWow64Mode)
		{
			// If address is already retrieved, no need to re-prepare
			if (PebAddress != 0)
			{
				return;
			}

			auto NtdllHandle = GetModuleHandle(L"ntdll.dll");
			if (NtdllHandle == nullptr || NtdllHandle == INVALID_HANDLE_VALUE)
			{
				THROW_EXCEPTION_FORMATTED_MESSAGE("Failed to get a handle to ntdll, will fail to retrieve the remote process PEB and modules");
			}

			auto NtQueryInformationProcessPtr = reinterpret_cast<NtQueryInformationProcessDecl>(
				GetProcAddress(NtdllHandle, "NtWow64QueryInformationProcess64"));

			if (NtQueryInformationProcessPtr == nullptr)
			{
				THROW_EXCEPTION_FORMATTED_MESSAGE("Failed to get pointer to NtQueryInformationProcess, will fail to retrieve the remote process PEB and modules");
			}

			PROCESS_BASIC_INFORMATION64 ProcInformation;
			DWORD ProcessInformationLength = sizeof(PROCESS_BASIC_INFORMATION64);
			DWORD StructReturnLength = 0;

			// Call the function pointer
			auto Status = NtQueryInformationProcessPtr(
				ProcessHandle.get(), ProcessBasicInformation, &ProcInformation, ProcessInformationLength, &StructReturnLength);

			if (FAILED(Status) || ProcessInformationLength != StructReturnLength)
			{
				THROW_EXCEPTION_FORMATTED_MESSAGE("Call to NtWow64QueryInformationProcess64 has failed with status = "
					<< std::hex << Status << ", will fail to retrieve the remote process PEB and modules");
			}

			PebAddress = ProcInformation.PebBaseAddress;
			return;
		}

		auto PsapiHandle = LoadLibrary(L"psapi.dll");
		if (PsapiHandle == NULL)
		{
			// We cannot continue enumeration without a handle to psapi
			THROW_EXCEPTION_FORMATTED_MESSAGE(L"Failed to load PSAPI.dll, cannot properly enumerate remote process modules");
		}

		// Just get addresses to the following functions, if any of them fails we cannot continue
		EnumProcessModulesExPtr = reinterpret_cast<FEnumProcessModulesExPtr>(GetProcAddress(PsapiHandle, "EnumProcessModulesEx"));
		GetModuleFilenameExWPtr = reinterpret_cast<FGetModuleFileNameExWPtr>(GetProcAddress(PsapiHandle, "GetModuleFileNameExW"));
		GetModuleBaseNameWPtr = reinterpret_cast<FGetModuleBaseNameWPtr>(GetProcAddress(PsapiHandle, "GetModuleBaseNameW"));
		GetModuleInformationPtr = reinterpret_cast<FGetModuleInformationPtr>(GetProcAddress(PsapiHandle, "GetModuleInformation"));

		if (GetModuleInformationPtr == nullptr || GetModuleBaseNameWPtr == nullptr || GetModuleFilenameExWPtr == nullptr || EnumProcessModulesExPtr == nullptr)
		{
			THROW_EXCEPTION_FORMATTED_MESSAGE(L"Failed to load a PSAPI function for process module enumeration, cannot continue enumeration");
		}
	}
	*/


	const ModuleInformation& ProcessModuleInspector::GetModuleByName(const std::string& ModuleName, EModuleBitness ModBitness) const
	{
		// Determine the bitness of the module by the bitness of the process
		// Usually we;ll have 64bit modules in a 64bit process and vice verca
		// Obvioiusly, this is not always true, for example: wow64.dll in a 32bit process on a 64bit OS
		if (ModBitness == EModuleBitness::AUTOMATIC)
		{
			ModBitness = (ProcInfoInspector->IsProcess64Bit) ? EModuleBitness::BIT_64 : EModuleBitness::BIT_32;
		}

		const auto& FoundMapIter = ProcessModuleMap.find(std::make_pair(ModuleName, ModBitness));
		if (FoundMapIter != ProcessModuleMap.cend())
		{
			LOG_VERBOSE << L"Found address: " << std::hex << FoundMapIter->second.ModuleBase << L" for module: " << ModuleName;
			return FoundMapIter->second;
		}

		// Throw here if not found
		THROW_EXCEPTION_FORMATTED_MESSAGE("Not able to find module: " + ModuleName);
	}

	void ProcessModuleInspector::ProcessNewModule(const DWORD64 ModuleBase, const DWORD ModuleSize)
	{
		// Create the structure and get the buffer
		ModuleInformation ModuleData;
		ModuleData.ModuleBase = ModuleBase;
		ModuleData.ModuleSize = ModuleSize;

		ModuleData.ModuleBuffer = ProcMemInspector->ReadBufferFromProcess(ModuleBase, ModuleSize);
		if (ModuleData.ModuleBuffer.size() == 0)
		{
			THROW_EXCEPTION_FORMATTED_MESSAGE("Failed to retrieve a buffer of module located at base: " << std::hex << ModuleBase);
		}

		// Next we get bitness and the name
		auto ModBaseInBuffer = reinterpret_cast<unsigned char *>(&ModuleData.ModuleBuffer[0]);
		auto BufferLimit = reinterpret_cast<DWORD64>(ModBaseInBuffer + ModuleSize);

		auto DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(ModBaseInBuffer);

		// Signature of the DOS header is fixed, this will probably always be ok
		if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			THROW_EXCEPTION_FORMATTED_MESSAGE("Incompatible magic of the DOS header of pe image read from: " << std::hex << ModuleBase);
		}

		auto NtHeadersPtr = ModBaseInBuffer + DosHeader->e_lfanew;
		if (reinterpret_cast<DWORD64>(NtHeadersPtr) >= BufferLimit)
		{
			THROW_EXCEPTION_FORMATTED_MESSAGE("NT Headers ptr is larger than the buffer size ");
		}

		auto HeadersPtr = reinterpret_cast<IMAGE_NT_HEADERS *>(NtHeadersPtr);
		ModuleData.ModuleBitness = (HeadersPtr->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) ? EModuleBitness::BIT_64 : EModuleBitness::BIT_32;

		// Signature of the NT header is also fixed
		if (HeadersPtr->Signature != IMAGE_NT_SIGNATURE)
		{
			THROW_EXCEPTION_FORMATTED_MESSAGE("Incompatible signature pe image read from: " << std::hex << ModuleBase);
		}

		// 64 bit modules have a different rva
		DWORD RvaToExportDir = 0;
		if (ModuleData.ModuleBitness == EModuleBitness::BIT_64)
		{
			auto NtHeader = reinterpret_cast<IMAGE_NT_HEADERS64 *>(NtHeadersPtr);
			RvaToExportDir = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		}
		else
		{
			auto NtHeader = reinterpret_cast<IMAGE_NT_HEADERS32 *>(NtHeadersPtr);
			RvaToExportDir = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		}

		// The module name resides in the export directory
		auto ExportDirectoryPtr = reinterpret_cast<IMAGE_EXPORT_DIRECTORY *>(ModBaseInBuffer + RvaToExportDir);
		auto ModuleNamePtr = reinterpret_cast<const char *>(ModBaseInBuffer + ExportDirectoryPtr->Name);
		if (reinterpret_cast<DWORD64>(ExportDirectoryPtr) >= BufferLimit || reinterpret_cast<DWORD64>(ModuleNamePtr) >= BufferLimit)
		{
			THROW_EXCEPTION_FORMATTED_MESSAGE("Export directory ptr or module name ptr is larger than the buffer size ");
		}

		std::string ModuleName(ModuleNamePtr);
		if (ModuleName.empty())
		{
			LOG_WARNING << L"Found a PE image in the target process with no name, this is probably the exeuctable itself, safe to skip";
			return;
		}

		// Lowercase the name before storing it
		auto ModuleNameLc = ModuleName;
		std::transform(ModuleName.begin(), ModuleName.end(), ModuleNameLc.begin(),
			[](auto Character)
			{
				return std::tolower(Character);
			});

		ProcessModuleMap.insert(std::make_pair(std::make_pair(ModuleNameLc, ModuleData.ModuleBitness), ModuleData));
		
		LOG_DEBUG << L"Retrieved information about module: "
			<< L"Name: " << ModuleNameLc
			<< L", Base: " << std::hex << ModuleData.ModuleBase
			<< L", Bitness: " << ((ModuleData.ModuleBitness == EModuleBitness::BIT_64) ? L"64bit" : L"32bit");
	}

	/*
	void ProcessModuleInspector::LoadInformationInternal(const std::wstring & SpecificModuleName)
	{
		// Allocate the module array on the stack, a normal process should not have more than MAX_ENUMERATED_MODULE_NUM modules
		std::array< HMODULE, MAX_ENUMERATED_MODULE_NUM > ModuleListArr;


		DWORD ActualBytesNeededForArr = 0;
		DWORD ModuleListBufferSize = static_cast<DWORD>(sizeof(HMODULE) * MAX_ENUMERATED_MODULE_NUM);

		if (!EnumProcessModulesExPtr(ProcessHandle.get(), ModuleListArr.data(), ModuleListBufferSize, &ActualBytesNeededForArr, LIST_MODULES_ALL))
		{
			THROW_EXCEPTION_FORMATTED_MESSAGE(L"Failed to enumerate process modules for Process Handle: "
				<< std::hex << ProcessHandle.get());
		}

		// We need a big buffer, this should never happen in reality
		if (ActualBytesNeededForArr > ModuleListBufferSize)
		{
			THROW_EXCEPTION_FORMATTED_MESSAGE(L"Allocated buffer for the enumerated module list is not big enough somehow, process contains more modules than MAX_ENUMERATED_MODULE_NUM");
		}

		for (auto& ModulePtr : ModuleListArr)
		{
			// Get information about the module size and its base allocation location
			MODULEINFO	ModuleInfo;
			if (!GetModuleInformationPtr(ProcessHandle.get(), ModulePtr, &ModuleInfo, sizeof(ModuleInfo)))
			{
				continue;
			}

			// Get module path, filesystem path to the module file
			std::array< wchar_t, MAX_STRING_LEN > ModulePathname;
			if (GetModuleFilenameExWPtr(ProcessHandle.get(), ModulePtr, ModulePathname.data(), MAX_STRING_LEN) == 0)
			{
				continue;
			}

			ModuleInformation ModuleData;
			ModuleData.ModuleBase = reinterpret_cast<DWORD64>(ModuleInfo.lpBaseOfDll);
			ModuleData.ModuleSize = ModuleInfo.SizeOfImage;
			ModuleData.ModulePath = ModulePathname.data();

			// Determine bitness of the module by reading the PE header of the module
			ModuleData.ModuleBuffer = ReadModuleToBuffer(ModuleData.ModuleBase, ModuleData.ModuleSize);
			ModuleData.ModuleBitness = (IsModule64bitInternal(ModuleData.ModuleBuffer)) ? EModuleBitness::BIT_64 : EModuleBitness::BIT_32;

			// Put the modulename into lowercase mode
			auto ModuleName = ModuleData.ModulePath.stem().string();
			auto ModuleNameLc = ModuleName;

			std::transform(ModuleName.begin(), ModuleName.end(), ModuleNameLc.begin(),
				[](auto Character)
				{
					return std::tolower(Character);
				});
			ProcessModuleMap.insert(std::make_pair(std::make_pair(ModuleNameLc, ModuleData.ModuleBitness), ModuleData));
		}

		if (ProcessModuleMap.size() == 0)
		{
			THROW_EXCEPTION_FORMATTED_MESSAGE(L"Was only able to enumerate 0 modules!");
		}

		LOG_DEBUG << L"Successefully enumerated " << ProcessModuleMap.size() << L" modules";
	}

	void ProcessModuleInspector::LoadModuleFromLdrEntry(const LDR_DATA_TABLE_ENTRY64& Entry)
	{
		// Skip an empty ldr data table entry
		if (Entry.DllBase == 0)
		{
			return;
		}

		ModuleInformation ModuleData;
		ModuleData.ModuleBase = Entry.DllBase;
		ModuleData.ModuleSize = Entry.SizeOfImage;

		// Read the module path
		std::wstring Path(L'a', Entry.FullDllName.Length);
		auto PathBuffer = ProcMemInspector->ReadBufferFromProcess(Entry.FullDllName.Buffer, Entry.FullDllName.Length);
		Path.assign(
			reinterpret_cast<const wchar_t *>(&PathBuffer[0]),
			PathBuffer.size() / sizeof(wchar_t));

		ModuleData.ModulePath = Path;

		// Read the module name
		auto NameBuffer = ProcMemInspector->ReadBufferFromProcess(Entry.BaseDllName.Buffer, Entry.BaseDllName.Length);
		ModuleData.ModuleName.assign(
			reinterpret_cast<const wchar_t *>(&NameBuffer[0]),
			NameBuffer.size() / sizeof(wchar_t));

		// Determine bitness of the module by reading the PE header of the module
		ModuleData.ModuleBuffer = ReadModuleToBuffer(ModuleData.ModuleBase, ModuleData.ModuleSize);
		ModuleData.ModuleBitness = (IsModule64bitInternal(ModuleData.ModuleBuffer)) ? EModuleBitness::BIT_64 : EModuleBitness::BIT_32;

		// Put the modulename into lowercase mode
		auto ModuleNameLc = ModuleData.ModulePath.filename().string();

		std::transform(ModuleData.ModuleName.begin(), ModuleData.ModuleName.end(), ModuleNameLc.begin(),
			[](auto Character)
			{
				return std::tolower(Character);
			});

		ProcessModuleMap.insert(std::make_pair(std::make_pair(ModuleNameLc, ModuleData.ModuleBitness), ModuleData));


		LOG_DEBUG << L"Retrieved information about module: "
			<< L"Name: " << ModuleNameLc
			<< L", Base: " << std::hex << ModuleData.ModuleBase
			<< L", Bitness: " << ((ModuleData.ModuleBitness == EModuleBitness::BIT_64) ? L"64bit" : L"32bit");
		
	}


	void ProcessModuleInspector::LoadInformationInternalWithPeb64(const std::wstring& SpecificModuleName)
	{
		if (PebAddress == 0)
		{
			THROW_EXCEPTION_FORMATTED_MESSAGE(L"Peb address is zero when trying to get module information, will abort");
		}

		// Note: This is not the full PEB, the structure is cutoff to have the things we require
		PEB64 Peb;
		if (!TryGetStructFromRemoteProcess(PebAddress, &Peb))
		{
			THROW_EXCEPTION_FORMATTED_MESSAGE(L"Failed to retrieve the PEB buffer from the remote process, will abort");
		}

		// Get the ldr structure using the pointer to it that sits in the peb
		PEB_LDR_DATA64 Ldr;
		if (!TryGetStructFromRemoteProcess(Peb.Ldr, &Ldr))
		{
			THROW_EXCEPTION_FORMATTED_MESSAGE(L"Failed to retrieve the Ldr buffer from the remote process, will abort");
		}

		// This is the head entry of the module list, this is usually the process image itself
		auto ListEntrySize = sizeof(LIST_ENTRY64);

		// Get the head entry, then iterate from it to it
		LDR_DATA_TABLE_ENTRY64 HeadEntry;

		// Simulate CONTAINING_RECORD macro, Blink actually points to the next InMemoryOrderModuleList member
		// of the next entry. But this member is not at the beginning of the structure
		// To get the address of the beginning of the structure, we must substract the size of the first
		// member of the structure, which is also a list entry
		auto HeadEntryPtr = Ldr.InMemoryOrderModuleList.Blink - ListEntrySize;
		TryGetStructFromRemoteProcess(HeadEntryPtr, &HeadEntry);

		auto NextEntryPtr = HeadEntry.InMemoryOrderModuleList.Blink - ListEntrySize;
		do
		{
			LDR_DATA_TABLE_ENTRY64 LdrEntry;

			if (!TryGetStructFromRemoteProcess(NextEntryPtr, &LdrEntry))
			{
				// We cannot continue we failed to retrieve an entry
				// That is because we won't have pointers to any following entry
				// So there is no point in continuing
				// We don't throw an exception here because we might have managed
				// to load something
				LOG_WARNING << L"Failed to retrieve a LDR_DATA_TABLE_ENTRY64 from the remote process"
					<< L", stopping module enumeration";
				break;
			}

			LoadModuleFromLdrEntry(LdrEntry);
			NextEntryPtr = LdrEntry.InMemoryOrderModuleList.Blink - ListEntrySize;

		} while (NextEntryPtr != HeadEntryPtr);

		LOG_DEBUG << L"Successefully loaded " << ProcessModuleMap.size() << L" modules";
	
	}
		*/
}