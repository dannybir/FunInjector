
#include "pch.h"
#include "FuncHookProcessInjector.h"
#include "AssemblyCodeGenerator.h"

namespace FunInjector
{
	FuncHookProcessInjector::FuncHookProcessInjector( const DWORD ProcessId, const std::string& DllName, const std::string& FunctionName )
		: IProcessInjector( ProcessId, DllName ), TargetFunctionName(FunctionName)
	{
	}


	FuncHookProcessInjector::~FuncHookProcessInjector()
	{
	}

	EOperationStatus FuncHookProcessInjector::InjectDll() noexcept
	{
		// Steps for injection are:
		// Write Injection Code
		// Write DllPath
		// 
		
		// First we write the path to the dll at the beginning of the payload address
		ByteBuffer DllPath( DllToInject.begin(), DllToInject.end() );
		DllPath.push_back('\0');
		if (ProcessUtils.WriteBufferToProcess(DllPath, PayloadAddress, DllPath.size()) == EOperationStatus::FAIL)
		{
			return EOperationStatus::FAIL;
		}

		// Need to append the payload address the size of the path buffer
		PayloadAddress += static_cast<DWORD64>( DllPath.size() );

		// Now write the original function bytes that we overwrote previously
		// We write them back so that we overwrite the original function with its original code once injection ends
		if (ProcessUtils.WriteBufferToProcess(TargetFunctionStartBackup, PayloadAddress, TargetFunctionStartBackup.size()) == EOperationStatus::FAIL)
		{
			return EOperationStatus::FAIL;
		}
		PayloadAddress += static_cast<DWORD64>(TargetFunctionStartBackup.size());

		auto CodeStart = PayloadAddress;

		auto VProtectCode = GenerateVirtualProtectCode(ProcessUtils, TargetFunctionAddress, TargetFunctionStartBackup.size(), PAGE_EXECUTE_WRITECOPY);
		if (ProcessUtils.WriteBufferToProcess(VProtectCode, PayloadAddress, VProtectCode.size()) == EOperationStatus::FAIL)
		{
			return EOperationStatus::FAIL;
		}
		PayloadAddress += static_cast<DWORD64>(VProtectCode.size());

		// After we write the hook, we need to call FlushInstructionCache
		//auto UnhookCode = GenerateUnhookCode(ProcessUtils, TargetFunctionAddress, PayloadAddress, TargetFunctionStartBackup.size());
		//if (ProcessUtils.WriteBufferToProcess(UnhookCode, PayloadAddress, UnhookCode.size()) == EOperationStatus::FAIL)
		//{
		//	return EOperationStatus::FAIL;
		//}



		// write hook
		JmpHookBuffer = GenerateRelativeJumpCode(TargetFunctionAddress, CodeStart);
		ProcessUtils.WriteBufferToProcess(JmpHookBuffer, TargetFunctionAddress, JmpHookBuffer.size());
	}

	EOperationStatus FuncHookProcessInjector::PrepareForInjection() noexcept
	{
		// 
		if (PrepareProcInfoUtils() == EOperationStatus::FAIL)
		{
			return EOperationStatus::FAIL;
		}

		TargetFunctionAddress = ProcessUtils.GetFunctionAddress(TargetFunctionName);
		if (TargetFunctionAddress == 0)
		{
			return EOperationStatus::FAIL;
		}

		// Find some free memory and allocate big enough memory
		// TODO: Hardcoded for now
		PayloadAddress = ProcessUtils.FindAndAllocateExecuteMemoryInProcess(0x100);
		if (PayloadAddress)
		{
			return EOperationStatus::FAIL;
		}

		//
		JmpHookBuffer = GenerateRelativeJumpCode(TargetFunctionAddress, PayloadAddress);
		TargetFunctionStartBackup = ProcessUtils.ReadBufferFromProcess(TargetFunctionAddress, JmpHookBuffer.size());

		// Generate a buffer with injection payload assembly code
		// We need to know how the big this buffer is before we can allocate remote memory for it




		
	}

	EOperationStatus FuncHookProcessInjector::PrepareProcInfoUtils() noexcept
	{
		auto ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessId);
		if (ProcessHandle == nullptr)
		{
			LOG_ERROR << L"Failed to open process handle for process id: " << ProcessId;
			return EOperationStatus::FAIL;
		}

		ProcessUtils = ProcessInformationUtils(ProcessHandle, false);
		return ProcessUtils.EnumerateProcessModules();
	}
	EOperationStatus FuncHookProcessInjector::CreateInjectionCodeBuffer() noexcept
	{
		//
		// 1. VirtualProtect the TargetFunctionAddress to make it writeable
		// 2. Memcpy from original function backup buffer to the target function address, effectivily removing the hook
		// 3. VirtualProtect to restore the previous protection
		// 4. FlushInstructionCache because we updated an instruction that may have been cached
		// 5. Call LoadLibrary with the dll path 
		// 6. Jmp to target function address

		// VirtualProtect( TargetFunctionAddress, SizeOfJmpHook, PAGE_EXECUTE_WRITECOPY, ... )
		auto VProtectCode = GenerateVirtualProtectCode(ProcessUtils, TargetFunctionAddress, TargetFunctionStartBackup.size(), PAGE_EXECUTE_WRITECOPY);

		auto MemCpyCode = GenerateMemCpyCode(ProcessUtils, TargetFunctionAddress, 0x50, TargetFunctionStartBackup.size());

		return EOperationStatus::SUCCESS;
	}
}

