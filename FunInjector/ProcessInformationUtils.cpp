
#include "pch.h"
#include "ProcessUtils.h"
#include "Utils.h"

namespace FunInjector::ProcessUtils
{
	/*
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
			if (!PerformWinApiCall(L"SymCleanup", SymCleanup, ProcessHandle))
			{
				LOG_WARNING << L"Failed to clear symbol information, might encounter unexpected results in module enumeration";
			}
			// Close the handle, its not needed anymore
			if (!PerformWinApiCall(L"CloseHandle", CloseHandle, ProcessHandle))
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

	DWORD64 ProcessInformationUtils::GetModuleAddress(const std::wstring &ModuleName) const noexcept
	{

	}

	DWORD64 ProcessInformationUtils::GetFunctionAddress(const std::wstring_view FunctionName) const noexcept
	{
		SYMBOL_INFOW Symbol{ 0 };
		Symbol.SizeOfStruct = sizeof(SYMBOL_INFOW);
		if (!SymFromNameW(ProcessHandle, FunctionName.data(), &Symbol))
		{
			LOG_ERROR << L"Failed to get symbol information for function: " << FunctionName;
			return 0;
		}

		LOG_DEBUG << L"Found address: " << std::hex << Symbol.Address << L" for function: " << FunctionName;
		return Symbol.Address;
	}

	bool ProcessUtils::ProcessInformationUtils::Is64BitProcess() const noexcept
	{
		return false;
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

	std::wstring ProcessUtils::ProcessInformationUtils::GetProcessName() const noexcept
	{
		return std::wstring();
	}


	EOperationStatus ProcessInformationUtils::LoadSymbolsForProcessModules()
	{

	}

	EOperationStatus ProcessInformationUtils::LoadSymbolForModule(const std::wstring_view ModulePath, const std::wstring_view ModuleName, DWORD64 ModuleBase, DWORD ModuleSize)
	{
		// SymLoadModule loads symbols for the supplied module, but in deffered mode, that information is not actually created until SymGetModuleInfo is called
		// So its very important to call SymGetModuleInfo AFTER SymLoadModule everytime!

		// For 64bit processes, sometimes SymLoadModuleExW may return 0 with a last error of 0, this means it has been successeful
		// So we need to continue anyway

		if (ProcessModuleMap.find(std::wstring(ModuleName)) != ProcessModuleMap.end())
		{
			return EOperationStatus::SUCCESS;
		}

		auto LoadedBaseAddr = SymLoadModuleExW(ProcessHandle, NULL, ModulePath.data(), ModuleName.data(), ModuleBase, ModuleSize, NULL, 0);
		auto LastError = GetLastError();
		if ( LoadedBaseAddr == 0 && LastError != 0 )
		{
			LOG_WARNING << L"SymLoadModuleExW failed for module: " << ModulePath << L", Error= " << std::hex << LastError;
			return EOperationStatus::FAIL;
		}

		IMAGEHLP_MODULEW64 ModuleAdditionalInfo;
		ModuleAdditionalInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULEW64);
		if (!PerformWinApiCall( L"SymGetModuleInfoW64", SymGetModuleInfoW64, ProcessHandle, ModuleBase, &ModuleAdditionalInfo))
		{
			LOG_WARNING << L"SymGetModuleInfoW64 failed for module: " << ModulePath << L", Error= " << std::hex << GetLastError();;
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
	*/
}

