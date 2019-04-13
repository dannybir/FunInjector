
#include "pch.h"
#include "ProcessInformationUtils.h"
#include "Utils.h"

namespace FunInjector
{
	using namespace FunInjector::Utils;

	ProcessInformationUtils::ProcessInformationUtils(HANDLE ProcHandle, bool Enumerate) : ProcessHandle(ProcHandle)
	{
		if (Enumerate)
		{
			if (EnumerateProcessModules() == EOperationStatus::FAIL)
			{
				LOG_ERROR << L"Failed to enumerate modules for process handle: " << std::hex << ProcHandle;
			}
		}
	}

	ProcessInformationUtils::~ProcessInformationUtils()
	{
		// Make sure handle is ok
		if (ProcessHandle == INVALID_HANDLE_VALUE || ProcessHandle == nullptr)
		{
			if (!PerformWinApiCall("SymCleanup", SymCleanup, ProcessHandle))
			{
				LOG_WARNING << L"Failed to clear symbol information, might encounter unexpected results in module enumeration";
			}
			// Close the handle, its not needed anymore
			if (!PerformWinApiCall("CloseHandle", CloseHandle, ProcessHandle))
			{
				LOG_ERROR << L"Failed to close handle: " << std::hex << ProcessHandle << L", handle will leak";
			}
		}


	}

	EOperationStatus ProcessInformationUtils::RefreshProcessModulesInfo()
	{
		if (LoadSymbolsForProcessModules() == EOperationStatus::FAIL)
		{
			return EOperationStatus::FAIL;
		}

		return EOperationStatus::SUCCESS;
	}

	DWORD64 ProcessInformationUtils::GetModuleAddress(const std::string &ModuleName) const noexcept
	{
		const auto& FoundMapIter = ProcessModuleMap.find(ModuleName);
		if (FoundMapIter != ProcessModuleMap.cend())
		{
			LOG_DEBUG << L"Found address: " << std::hex << FoundMapIter->second.BaseOfImage << L" for module: " << ModuleName;
			return FoundMapIter->second.BaseOfImage;
		}

		LOG_WARNING << L"Unable to find module: " << ModuleName << L" in the process module map, a refresh or enumeration may be needed";
		return 0;
	}

	DWORD64 ProcessInformationUtils::GetFunctionAddress(const std::string_view FunctionName) const noexcept
	{
		SYMBOL_INFO Symbol{ 0 };
		Symbol.SizeOfStruct = sizeof(SYMBOL_INFO);
		if (!SymFromName(ProcessHandle, FunctionName.data(), &Symbol))
		{
			LOG_ERROR << L"Failed to get symbol information for function: " << FunctionName;
			return 0;
		}

		LOG_DEBUG << L"Found address: " << std::hex << Symbol.Address << L" for function: " << FunctionName;
		return Symbol.Address;
	}

	ByteBuffer ProcessInformationUtils::ReadBufferFromProcess(DWORD64 ReadAddress, SIZE_T ReadSize) const noexcept
	{
		// This is the buffer we will read into, pre-allocate with supplied size
		ByteBuffer ReadBuffer(ReadSize);
		SIZE_T ActualReadSize = 0;

		if (ReadProcessMemory(ProcessHandle, reinterpret_cast<PVOID>(ReadAddress), &ReadBuffer[0], ReadSize, &ActualReadSize))
		{
			// Check that we read the amount we wanted
			if (ReadSize == ActualReadSize)
			{
				return ReadBuffer;
			}

			LOG_ERROR << L"Tried to read: " << ReadSize << L" bytes from from memory address: " << std::hex << ReadAddress
				<< L", but was only able to read: " << ActualReadSize << L", will return an empty buffer instead";
			return ByteBuffer();
		}

		LOG_ERROR << L"Failed to read: " << ReadSize << L" bytes from from memory address: " << std::hex << ReadAddress
			<< L", there might be an issue with access qualifiers for the process handle, will return an empty buffer, Error=" << GetLastError();

		return ByteBuffer();
	}

	EOperationStatus ProcessInformationUtils::WriteBufferToProcess(const ByteBuffer& WriteBuffer, DWORD64 WriteAddress, SIZE_T WriteSize) const noexcept
	{
		// This is the buffer we will read into, pre-allocate with supplied size
		SIZE_T ActualWriteSize = 0;

		if (WriteProcessMemory(ProcessHandle, reinterpret_cast<PVOID>(WriteAddress), &WriteBuffer[0], WriteSize, &ActualWriteSize))
		{
			// Check that we read the amount we wanted
			if (WriteSize == ActualWriteSize)
			{
				LOG_DEBUG << L"Succussefully written: " << ActualWriteSize << L" bytes to address: " << std::hex << WriteAddress;
				return EOperationStatus::SUCCESS;
			}

			LOG_ERROR << L"Tried to write: " << WriteSize << L" bytes to from memory address: " << std::hex << WriteAddress
				<< L", but was only able to write: " << ActualWriteSize << L", consider this operation as failed";
			return EOperationStatus::FAIL;
		}

		LOG_ERROR << L"Failed to write: " << WriteSize << L" bytes from to memory address: " << std::hex << WriteAddress
			<< L", there might be an issue with access qualifiers for the process handle, consider this operation as failed, Error=" << GetLastError();

		return EOperationStatus::FAIL;
	}

	DWORD64 ProcessInformationUtils::FindFreeMemoryRegion(DWORD64 ScanLocation, SIZE_T FreeMemorySize, bool ScanDown ) const noexcept
	{
		PVOID ScanLocationPtr = reinterpret_cast<PVOID>(ScanLocation);

		// Get information about the memory layout at the start of the scan location
		MEMORY_BASIC_INFORMATION MemInfo{ 0 };
		if (VirtualQueryEx(ProcessHandle, ScanLocationPtr, &MemInfo, sizeof(MemInfo)) == 0)
		{
			LOG_ERROR << L"Tried to VirtualQuery memory address: " << std::hex << L", but this failed with Error= " << std::hex << GetLastError();
			return 0;
		}

		// Keep trying to find a region big enough to fit 
		while (MemInfo.State != MEM_FREE || MemInfo.RegionSize < FreeMemorySize )
		{
			// Go up/down in addresses depenending on ScanDown parameter, skip entire unwanted regions
			int DirectionMultiplier = (ScanDown) ? -1 : 1;
			ScanLocationPtr = reinterpret_cast<PVOID>(reinterpret_cast<DWORD64>(ScanLocationPtr) + (DirectionMultiplier * MemInfo.RegionSize));

			if (VirtualQueryEx(ProcessHandle, ScanLocationPtr, &MemInfo, sizeof(MemInfo)) == 0)
			{
				LOG_ERROR << L"Tried to VirtualQuery memory address: " << std::hex << L", but this failed with Error= " << std::hex << GetLastError();
				return 0;
			}

			if (reinterpret_cast<DWORD64>(MemInfo.BaseAddress) == 0)
			{
				// Probably reached memory start here and found nothing
				LOG_WARNING << L"While looking for free memory, got to region with BaseAddress = 0";
				return 0;
			}
		}

		LOG_DEBUG << L"Found a free memory region with size: " << MemInfo.RegionSize << L", in location: " << std::hex << MemInfo.BaseAddress;
		return reinterpret_cast<DWORD64>(ScanLocationPtr);
	}

	DWORD64 ProcessInformationUtils::AllocateMemoryInProcessForExecution(DWORD64 MemoryAddress, SIZE_T AllocationSize) const noexcept
	{
		PVOID AllocationBase = VirtualAllocEx(ProcessHandle, reinterpret_cast<PVOID>(MemoryAddress), AllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (AllocationBase != nullptr)
		{
			LOG_DEBUG << L"Successefully Allocated: " << AllocationSize << L" bytes in memory address: "
				<< std::hex << MemoryAddress << L" with PAGE_EXECUTE_READWRITE protection";
			return reinterpret_cast<DWORD64>(AllocationBase);
		}

		// If allocating PAGE_EXECUTE_READWRITE fails, try to allocate instead PAGE_READWRITE and then reprotecting the memory
		LOG_WARNING << L"Failed to allocate: " << AllocationSize << L" bytes in memory address: "
			<< std::hex << MemoryAddress << L" with PAGE_EXECUTE_READWRITE protection, Error= " << GetLastError();

		AllocationBase = VirtualAllocEx(ProcessHandle, reinterpret_cast<PVOID>(MemoryAddress), AllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (AllocationBase == nullptr)
		{
			// We fail to allocate even a RW page, guess something is wrong with the process handle
			LOG_WARNING << L"Failed to allocate: " << AllocationSize << L" bytes in memory address: "
				<< std::hex << MemoryAddress << L" with PAGE_READWRITE protection. Process handle may have insufficent access priviliges"
				<< L", Error= " << GetLastError();

			return 0;
		}

		// Try to reprotect the page to be executeable
		DWORD OldProtect = 0;
		if (!VirtualProtectEx(ProcessHandle, AllocationBase, AllocationSize, PAGE_EXECUTE_READWRITE, &OldProtect))
		{
			LOG_ERROR << L"Failed to reprotect memory address: " << std::hex << AllocationBase << L" with PAGE_EXECUTE_READWRITE protection" 
				<< L", although allocation was successeful, the allocated is not executeable, so we return 0" << L", Error= " << GetLastError();;
			return 0;
		}

		LOG_DEBUG << L"Successefully Allocated: " << AllocationSize << L" bytes in memory address: "
			<< std::hex << MemoryAddress << L" with PAGE_EXECUTE_READWRITE protection";

		return reinterpret_cast<DWORD64>(AllocationBase);
	}

	EOperationStatus ProcessInformationUtils::EnumerateProcessModules()
	{
		// Make sure handle is ok
		if (ProcessHandle == INVALID_HANDLE_VALUE || ProcessHandle == nullptr)
		{
			LOG_ERROR << L"Supplied an invalid handle, cannot enumerate process modules";
			return EOperationStatus::FAIL;
		}

		// Initialize the symbol handler, we will use it to get information regarding modules and their functions in the remote process
		// We will let SymInitialize handle the module enumeration for us
		if (!PerformWinApiCall( "SymInitializeW", SymInitializeW ,ProcessHandle, L"", TRUE))
		{
			auto Error = GetLastError();
			LOG_WARNING << L"Failed to run SymInitialize, will not be able to properly enumarate remote process modules, Error= " << std::hex << Error;
			return EOperationStatus::FAIL;
		}

		// Edit the sym options to add SYMOPT_FAIL_CRITICAL_ERRORS to make sure we won't get any dialogs
		DWORD SymOptions = SymGetOptions();
		SymOptions |= SYMOPT_FAIL_CRITICAL_ERRORS;
		SymOptions |= SYMOPT_DEFERRED_LOADS;
		SymOptions |= SYMOPT_NO_PROMPTS;
		SymOptions = SymSetOptions(SymOptions);

		if (LoadSymbolsForProcessModules() == EOperationStatus::FAIL)
		{
			return EOperationStatus::FAIL;
		}

		return EOperationStatus::SUCCESS;
	}

	DWORD64 ProcessInformationUtils::FindAndAllocateExecuteMemoryInProcess(SIZE_T AllocSize) const noexcept
	{
		// First find free memory, we start the scan from location of ntdll.dll in the process
		// The OS will always allocate ntdll to the same address location for all the processes 
		DWORD64 NtdllAddress = GetModuleAddress("ntdll.dll");

		auto FreeMemoryRegionAddress = NtdllAddress;
		DWORD64 AllocationAddress = 0;
		// Scan down in addresses until a suitable memory region is found
		// If AllocSize is too big, its possible we won't find anything
		do
		{
			FreeMemoryRegionAddress = FindFreeMemoryRegion(FreeMemoryRegionAddress, AllocSize);
			AllocationAddress = AllocateMemoryInProcessForExecution(FreeMemoryRegionAddress, AllocSize);

		} while (FreeMemoryRegionAddress != 0 && AllocationAddress == 0);

		return AllocationAddress;
	}

	EOperationStatus ProcessInformationUtils::PrepareForModuleEnumeration()
	{
		auto PsapiHandle = LoadLibrary(L"psapi.dll");
		if (PsapiHandle == NULL)
		{
			LOG_ERROR << L"Failed to load PSAPI.dll, cannot properly enumerate remote process modules";
			// We cannot continue enumeration without a handle to psapi
			return EOperationStatus::FAIL;
		}

		// Just get addresses to the following functions, if any of them fails we cannot continue
		EnumProcessModulesExPtr = reinterpret_cast<FEnumProcessModulesExPtr>(GetProcAddress(PsapiHandle, "EnumProcessModulesEx"));
		GetModuleFilenameExPtr = reinterpret_cast<FGetModuleFileNameExPtr>(GetProcAddress(PsapiHandle, "GetModuleFileNameExA"));
		GetModuleBaseNamePtr = reinterpret_cast<FGetModuleBaseNamePtr>(GetProcAddress(PsapiHandle, "GetModuleBaseNameA"));
		GetModuleInformationPtr = reinterpret_cast<FGetModuleInformationPtr>(GetProcAddress(PsapiHandle, "GetModuleInformation"));

		if (GetModuleInformationPtr == nullptr || GetModuleBaseNamePtr == nullptr || GetModuleFilenameExPtr == nullptr || EnumProcessModulesExPtr == nullptr)
		{
			LOG_ERROR << L"Failed to load a PSAPI function for process module enumeration, cannot continue enumeration";
			return EOperationStatus::FAIL;
		}

		return EOperationStatus::SUCCESS;
	}

	EOperationStatus ProcessInformationUtils::LoadSymbolsForProcessModules()
	{
		// To load the modules, we must first enumerate them to get more information
		// We use the helpful psapi.dll and the functions it contains
		// psapi.dll is a standard Windows DLL which always resides in System32/SysWow64
		// We dynamically link in order to make sure we are using operating system compatible binaries
		if (PrepareForModuleEnumeration() == EOperationStatus::FAIL)
		{
			return EOperationStatus::FAIL;
		}

		// Allocate the module array on the stack, a normal process should not have more than MAX_ENUMERATED_MODULE_NUM modules
		HMODULE ModuleListArrPtr[MAX_ENUMERATED_MODULE_NUM];
		DWORD ActualBytesNeededForArr = 0;
		DWORD ModuleListBufferSize = static_cast<DWORD>(sizeof(HMODULE) * MAX_ENUMERATED_MODULE_NUM);

		if (!PerformWinApiCall("EnumProcessModulesExPtr", EnumProcessModulesExPtr,ProcessHandle, ModuleListArrPtr, ModuleListBufferSize, &ActualBytesNeededForArr, LIST_MODULES_ALL))
		{
			LOG_ERROR << L"Failed to enumerate process modules for Process Handle: " << std::hex << ProcessHandle;
			return EOperationStatus::FAIL;
		}

		// We need a big buffer, this should never happen in reality
		if (ActualBytesNeededForArr > ModuleListBufferSize)
		{
			LOG_ERROR << L"Allocated buffer for the enumerated module list is not big enough somehow, process contains more modules than MAX_ENUMERATED_MODULE_NUM";
			return EOperationStatus::FAIL;
		}

		// Iterate the retrieved module array and get some more information
		auto ModulesArrLength = ActualBytesNeededForArr / sizeof(HMODULE);
		int LoadedModules = 0;
		for (int i = 0; i < ModulesArrLength; i++)
		{
			// Get information about the module size and its base allocation location
			MODULEINFO	ModuleInfo;
			if (!GetModuleInformationPtr(ProcessHandle, ModuleListArrPtr[i], &ModuleInfo, sizeof(ModuleInfo)))
			{
				continue;
			}

			// Get module path, filesystem path to the module file
			CHAR ModulePathname[MAX_STRING_LEN] = { 0 };
			if (!PerformWinApiCall( "GetModuleFilenameExWPtr", GetModuleFilenameExPtr, ProcessHandle, ModuleListArrPtr[i], ModulePathname, MAX_STRING_LEN))
			{
				continue;
			}

			// Get module name
			CHAR ModuleName[MAX_STRING_LEN] = { 0 };
			if (!PerformWinApiCall( "GetModuleBaseNameWPtr", GetModuleBaseNamePtr,ProcessHandle, ModuleListArrPtr[i], ModuleName, MAX_STRING_LEN))
			{
				continue;
			}

			if (LoadSymbolForModule(ModulePathname, ModuleName, reinterpret_cast<DWORD64>(ModuleInfo.lpBaseOfDll), ModuleInfo.SizeOfImage) == EOperationStatus::SUCCESS)
			{
				LoadedModules++;
			}
		}

		if (LoadedModules == 0)
		{
			LOG_ERROR << L"Was able to enumerate 0 modules!";
			return EOperationStatus::FAIL;
		}

		LOG_INFO << L"Successefully enumerated " << LoadedModules << L" modules for process: " << ProcessName;
		return EOperationStatus::SUCCESS;
	}

	EOperationStatus ProcessInformationUtils::LoadSymbolForModule(const std::string_view ModulePath, const std::string_view ModuleName, DWORD64 ModuleBase, DWORD ModuleSize)
	{
		// SymLoadModule loads symbols for the supplied module, but in deffered mode, that information is not actually created until SymGetModuleInfo is called
		// So its very important to call SymGetModuleInfo AFTER SymLoadModule everytime!

		// For 64bit processes, sometimes SymLoadModuleExW may return 0 with a last error of 0, this means it has been successeful
		// So we need to continue anyway

		auto LoadedBaseAddr = SymLoadModuleEx(ProcessHandle, NULL, ModulePath.data(), ModuleName.data(), ModuleBase, ModuleSize, NULL, 0);
		auto LastError = GetLastError();
		if ( LoadedBaseAddr == 0 && LastError != 0 )
		{
			LOG_WARNING << L"SymLoadModuleExW failed for module: " << ModulePath << L", Error= " << std::hex << LastError;
			return EOperationStatus::FAIL;
		}

		IMAGEHLP_MODULEW64 ModuleAdditionalInfo;
		ModuleAdditionalInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULEW64);
		if (!PerformWinApiCall( "SymGetModuleInfoW64", SymGetModuleInfoW64, ProcessHandle, ModuleBase, &ModuleAdditionalInfo))
		{
			LOG_WARNING << L"SymGetModuleInfoW64 failed for module: " << ModulePath << L", Error= " << std::hex << GetLastError();;
			return EOperationStatus::FAIL;
		}

		const auto [ InsertedIter, IsInserted ] = ProcessModuleMap.insert_or_assign(std::string(ModuleName), ModuleAdditionalInfo);
		if (!IsInserted)
		{
			LOG_ERROR << L"Insertion to process module map unexepctedly failed, perhaps memory issues?";
			return EOperationStatus::FAIL;
		}

		return EOperationStatus::SUCCESS;
	}
}

