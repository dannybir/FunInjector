#include "pch.h"
#include "ProcessModuleInspector.h"

// For std::to_wllower
#include <cwctype>

namespace FunInjector::ProcessInspector
{
	ProcessModuleInspector::ProcessModuleInspector(wil::shared_handle ProcHandle) : ProcessHandle(ProcHandle)
	{
	}

	EOperationStatus ProcessModuleInspector::LoadInformation() noexcept
	{
		// To load the modules, we must first enumerate them to get more information
		// We use the helpful psapi.dll and the functions it contains
		// psapi.dll is a standard Windows DLL which always resides in System32/SysWow64
		// We dynamically link in order to make sure we are using operating system compatible binaries
		PrepareForModuleEnumeration();

		// Allocate the module array on the stack, a normal process should not have more than MAX_ENUMERATED_MODULE_NUM modules
		std::array< HMODULE, MAX_ENUMERATED_MODULE_NUM > ModuleListArr;

		DWORD ActualBytesNeededForArr = 0;
		DWORD ModuleListBufferSize = static_cast<DWORD>(sizeof(HMODULE) * MAX_ENUMERATED_MODULE_NUM);

		if (!EnumProcessModulesExPtr( ProcessHandle.get(), ModuleListArr.data(), ModuleListBufferSize, &ActualBytesNeededForArr, LIST_MODULES_ALL))
		{
			LOG_ERROR << L"Failed to enumerate process modules for Process Handle: " << std::hex << ProcessHandle.get();
			return EOperationStatus::FAIL;
		}

		// We need a big buffer, this should never happen in reality
		if (ActualBytesNeededForArr > ModuleListBufferSize)
		{
			LOG_ERROR << L"Allocated buffer for the enumerated module list is not big enough somehow, process contains more modules than MAX_ENUMERATED_MODULE_NUM";
			return EOperationStatus::FAIL;
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
			ModuleData.ModuleBuffer = GetModuleBuffer(ModuleData.ModuleBase, ModuleData.ModuleSize);
			ModuleData.ModuleBitness = (IsModule64bitInternal(ModuleData.ModuleBuffer)) ? EModuleBitness::BIT_64 : EModuleBitness::BIT_32;

			// Put the modulename into lowercase mode
			auto ModuleName = ModuleData.ModulePath.stem().string();
			auto ModuleNameLc = ModuleName;
			std::transform(ModuleName.begin(), ModuleName.end(), ModuleNameLc.begin(), std::towlower);

			ProcessModuleMap.insert(std::make_pair( std::make_pair(ModuleNameLc, ModuleData.ModuleBitness), ModuleData));
		}

		if (ProcessModuleMap.size() == 0)
		{
			LOG_ERROR << L"Was able to enumerate 0 modules!";
			return EOperationStatus::FAIL;
		}

		LOG_INFO << L"Successefully enumerated " << ProcessModuleMap.size() << L" modules";
		return EOperationStatus::SUCCESS;
	}

	DWORD64 ProcessModuleInspector::GetModuleAddress(const std::string & ModuleName, EModuleBitness ModBitness) const noexcept
	{
		auto ModuleInfo = GetModuleByName(ModuleName, ModBitness);
		return ModuleInfo.ModuleBase;
	}

	DWORD64 ProcessModuleInspector::GetModuleSize(const std::string & ModuleName, EModuleBitness ModBitness) const noexcept
	{
		auto ModuleInfo = GetModuleByName(ModuleName, ModBitness);
		return ModuleInfo.ModuleSize;
	}

	ByteBuffer ProcessModuleInspector::GetModuleBufferByName(const std::string & ModuleName, EModuleBitness ModBitness) const noexcept
	{
		auto ModuleInfo = GetModuleByName(ModuleName, ModBitness);
		if (ModuleInfo.ModuleBuffer.size() > 0)
		{
			return ModuleInfo.ModuleBuffer;
		}

		// May return an empty buffer if something goes wrong
		return ProcMemInspector->ReadBufferFromProcess(ModuleInfo.ModuleBase, static_cast<size_t>(ModuleInfo.ModuleSize));
	}

	void ProcessModuleInspector::PrepareForModuleEnumeration() noexcept
	{
		auto PsapiHandle = LoadLibrary(L"psapi.dll");
		if (PsapiHandle == NULL)
		{
			LOG_ERROR << L"Failed to load PSAPI.dll, cannot properly enumerate remote process modules";
			// We cannot continue enumeration without a handle to psapi
			//return EOperationStatus::FAIL;
		}

		// Just get addresses to the following functions, if any of them fails we cannot continue
		EnumProcessModulesExPtr = reinterpret_cast<FEnumProcessModulesExPtr>(GetProcAddress(PsapiHandle, "EnumProcessModulesEx"));
		GetModuleFilenameExWPtr = reinterpret_cast<FGetModuleFileNameExWPtr>(GetProcAddress(PsapiHandle, "GetModuleFileNameExW"));
		GetModuleBaseNameWPtr = reinterpret_cast<FGetModuleBaseNameWPtr>(GetProcAddress(PsapiHandle, "GetModuleBaseNameW"));
		GetModuleInformationPtr = reinterpret_cast<FGetModuleInformationPtr>(GetProcAddress(PsapiHandle, "GetModuleInformation"));

		if (GetModuleInformationPtr == nullptr || GetModuleBaseNameWPtr == nullptr || GetModuleFilenameExWPtr == nullptr || EnumProcessModulesExPtr == nullptr)
		{
			LOG_ERROR << L"Failed to load a PSAPI function for process module enumeration, cannot continue enumeration";
			//return EOperationStatus::FAIL;
		}
	}
	const ModuleInformation& ProcessModuleInspector::GetModuleByName(const std::string& ModuleName, EModuleBitness ModBitness) const
	{
		if (ModBitness == EModuleBitness::AUTOMATIC)
		{
			ModBitness = (ProcInfoInspector->IsProcess64Bit) ? EModuleBitness::BIT_64 : EModuleBitness::BIT_32;
		}

		const auto& FoundMapIter = ProcessModuleMap.find(std::make_pair(ModuleName, ModBitness));
		if (FoundMapIter != ProcessModuleMap.cend())
		{
			LOG_DEBUG << L"Found address: " << std::hex << FoundMapIter->second.ModuleBase << L" for module: " << ModuleName;
			return FoundMapIter->second;
		}

		// Throw here if not found
	}

	ByteBuffer ProcessModuleInspector::GetModuleBuffer(DWORD64 ModuleBaseAddress, DWORD64 ModuleSize) const
	{
		// May return an empty buffer if something goes wrong
		return ProcMemInspector->ReadBufferFromProcess(ModuleBaseAddress, static_cast<size_t>(ModuleSize));
	}

	bool ProcessModuleInspector::IsModule64bitInternal(ByteBuffer& ModuleBuffer) const
	{
		if (ModuleBuffer.size() == 0)
		{
			return ProcInfoInspector->IsProcess64Bit;
		}

		auto ModBaseInBuffer = reinterpret_cast<unsigned char *>(&ModuleBuffer[0]);
		auto DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(ModBaseInBuffer);

		// Signature of the DOS header is fixed, this will probably always be ok
		if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return 0;

		auto HeadersPtr = reinterpret_cast<IMAGE_NT_HEADERS *>(ModBaseInBuffer + DosHeader->e_lfanew);
		return (HeadersPtr->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) ? true : false;
	}
}