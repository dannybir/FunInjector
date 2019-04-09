
#include "pch.h"
#include "ProcessInformationUtils.h"

namespace FunInjector
{
	template <typename Func, typename ... FuncArgs>
	bool PerformWinApiCall(const std::wstring_view FuncName, Func&& FuncPtr, FuncArgs&& ... Args)
	{
		using RetType = std::invoke_result_t< Func, FuncArgs ... >;

		// Call the function
		auto Result = std::invoke(FuncPtr, Args...);

		// I am pessimistic :)
		bool InvokeSuccess = false;

		// if constexpr means here that compiled code would either have the first or second code in the final assembly result
		// is_same_v does compile time type comparison
		if constexpr (std::is_same_v< RetType, HRESULT >)
		{
			InvokeSuccess = Result == 0;
		}
		else if constexpr (std::is_same_v< RetType, BOOL> || std::is_same_v< RetType, DWORD> ||
						   std::is_same_v< RetType, DWORD64>)
		{
			InvokeSuccess = Result > 0;
		}
		else
		{
			static_assert(false, "Supplied function has a non-supported return type");
		}

		if (!InvokeSuccess)
		{
			LOG_ERROR << FuncName << L" failed, Error= " << GetLastError();
		}

		return InvokeSuccess;
	}

	ProcessInformationUtils::ProcessInformationUtils(HANDLE ProcHandle, bool Enumerate) : ProcessHandle(ProcHandle)
	{
		if (Enumerate)
		{
			EnumerateProcessModules();
		}
	}

	ProcessInformationUtils::~ProcessInformationUtils()
	{
		// Make sure handle is ok
		if (ProcessHandle == INVALID_HANDLE_VALUE || ProcessHandle == nullptr)
		{
			if (!PerformWinApiCall(L"SymCleanup", SymCleanup, ProcessHandle))
			{
				LOG_WARNING << L"Failed to clear symbol information, might encounter unexpected results in module enumeration";
			}
		}


	}

	EOperationStatus ProcessInformationUtils::RefreshProcessModulesInfo() const
	{
		if (!SymRefreshModuleList(ProcessHandle))
		{
			LOG_ERROR << L"Failed to refresh module information status, extracting information for modules might fail";
			return EOperationStatus::FAIL;
		}

		return EOperationStatus::SUCCESS;
	}

	DWORD64 ProcessInformationUtils::GetModuleAddress(const std::wstring &ModuleName) const
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

	DWORD64 ProcessInformationUtils::GetFunctionAddress(const std::wstring_view FunctionName) const
	{
		SYMBOL_INFOW Symbol{ 0 };
		Symbol.SizeOfStruct = sizeof(SYMBOL_INFO);
		if (!SymFromNameW(ProcessHandle, FunctionName.data(), &Symbol))
		{
			LOG_ERROR << L"Failed to get symbol information for function: " << FunctionName;
			return 0;
		}

		LOG_DEBUG << L"Found address: " << std::hex << Symbol.Address << L" for function: " << FunctionName;
		return Symbol.Address;
	}

	ByteBuffer ProcessInformationUtils::ReadBufferFromProcess(DWORD64 ReadAddress, SIZE_T ReadSize) const
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
		if (!PerformWinApiCall( L"SymInitializeW", SymInitializeW ,ProcessHandle, L"", TRUE))
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
		GetModuleFilenameExWPtr = reinterpret_cast<FGetModuleFileNameExWPtr>(GetProcAddress(PsapiHandle, "GetModuleFileNameExW"));
		GetModuleBaseNameWPtr = reinterpret_cast<FGetModuleBaseNameWPtr>(GetProcAddress(PsapiHandle, "GetModuleBaseNameW"));
		GetModuleInformationPtr = reinterpret_cast<FGetModuleInformationPtr>(GetProcAddress(PsapiHandle, "GetModuleInformation"));

		if (GetModuleInformationPtr == nullptr || GetModuleBaseNameWPtr == nullptr || GetModuleFilenameExWPtr == nullptr || EnumProcessModulesExPtr == nullptr)
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

		if (!PerformWinApiCall(L"EnumProcessModulesExPtr", EnumProcessModulesExPtr,ProcessHandle, ModuleListArrPtr, ModuleListBufferSize, &ActualBytesNeededForArr, LIST_MODULES_ALL))
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
			WCHAR ModulePathname[MAX_STRING_LEN];
			if (!PerformWinApiCall( L"GetModuleFilenameExWPtr", GetModuleFilenameExWPtr, ProcessHandle, ModuleListArrPtr[i], ModulePathname, MAX_STRING_LEN))
			{
				continue;
			}

			// Get module name
			WCHAR ModuleName[MAX_STRING_LEN];
			if (!PerformWinApiCall( L"GetModuleBaseNameWPtr", GetModuleBaseNameWPtr,ProcessHandle, ModuleListArrPtr[i], ModuleName, MAX_STRING_LEN))
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

		LOG_INFO << L"Successefully enumerated " << LoadedModules << L"modules for process:";
		return EOperationStatus::SUCCESS;
	}

	EOperationStatus ProcessInformationUtils::LoadSymbolForModule(const std::wstring_view ModulePath, const std::wstring_view ModuleName, DWORD64 ModuleBase, DWORD ModuleSize)
	{
		// SymLoadModule loads symbols for the supplied module, but in deffered mode, that information is not actually created until SymGetModuleInfo is called
		// So its very important to call SymGetModuleInfo AFTER SymLoadModule everytime!

		if (!SymLoadModuleExW(ProcessHandle, NULL, ModulePath.data(), ModuleName.data(), ModuleBase, ModuleSize, NULL, 0))
		{
			LOG_WARNING << L"SymLoadModuleExW failed for module: " << ModulePath;
			return EOperationStatus::FAIL;
		}

		IMAGEHLP_MODULEW64 ModuleAdditionalInfo;
		ModuleAdditionalInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULEW64);
		if (!PerformWinApiCall( L"SymGetModuleInfoW64", SymGetModuleInfoW64, ProcessHandle, ModuleBase, &ModuleAdditionalInfo))
		{
			LOG_WARNING << L"SymGetModuleInfoW64 failed for module: " << ModulePath;
			return EOperationStatus::FAIL;
		}

		const auto [ InsertedIter, IsInserted ] = ProcessModuleMap.insert_or_assign(std::wstring(ModuleName), ModuleAdditionalInfo);
		if (!IsInserted)
		{
			LOG_ERROR << L"Insertion to process module map unexepctedly failed, perhaps memory issues?";
			return EOperationStatus::FAIL;
		}

		return EOperationStatus::SUCCESS;
	}
}

