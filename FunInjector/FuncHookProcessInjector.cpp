
#include "pch.h"
#include "FuncHookProcessInjector.h"

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
		// First write the payload
		if (ProcessUtils.WriteBufferToProcess(PayloadBuffer, PayloadAddress, PayloadBuffer.size()) == EOperationStatus::FAIL)
		{
			return EOperationStatus::FAIL;
		}

		// Second, write the hook
		if (ProcessUtils.WriteBufferToProcess(JmpHookBuffer, TargetFunctionAddress, JmpHookBuffer.size()) == EOperationStatus::FAIL)
		{
			return EOperationStatus::FAIL;
		}

		return EOperationStatus::SUCCESS;
	}

	EOperationStatus FuncHookProcessInjector::PrepareForInjection() noexcept
	{
		if (PrepareProcInfoUtils() == EOperationStatus::FAIL)
		{
			return EOperationStatus::FAIL;
		}

		// Prepare the code manager, initiate it using the target process bitness so it could create correct assembly code
		CodeManager = AssemblyCodeManager(ECodeBitnessMode::X64);

		// Order is important here
		CodeManager.AddAssemblyCode("PushRegisters", ECodeType::PUSH_REGISTERS);
		CodeManager.AddAssemblyCode("RemoveProtection", ECodeType::VIRTUAL_PROTECT);
		CodeManager.AddAssemblyCode("CopyOriginalFunction", ECodeType::MEMCOPY);
		CodeManager.AddAssemblyCode("FlushInstructionCache", ECodeType::FLUSH_INSTRUCTION);
		CodeManager.AddAssemblyCode("LoadInjectedDLL", ECodeType::LOAD_DLL);
		CodeManager.AddAssemblyCode("PopRegisters", ECodeType::POP_REGISTERS);
		//

		CodeManager.AddAssemblyCode("JumpToOriginalFunction", ECodeType::RELATIVE_JUMP);

		TargetFunctionAddress = ProcessUtils.GetFunctionAddress(TargetFunctionName);
		if (TargetFunctionAddress == 0)
		{
			return EOperationStatus::FAIL;
		}

		PrepareDataPayload();

		// Find some free memory and allocate big enough memory
		SIZE_T PayloadSize = PayloadData.GetTotalDataSize() + CodeManager.GetTotalCodeSize();
		PayloadAddress = ProcessUtils.FindAndAllocateExecuteMemoryInProcess(PayloadSize + 0x50);
		if (PayloadAddress == 0)
		{
			return EOperationStatus::FAIL;
		}

		// Set up the jmp to the payload code
		auto JumpCode = AssemblyCode::PrepareRelativeJump(TargetFunctionAddress, PayloadAddress + PayloadData.GetTotalDataSize());
		JmpHookBuffer = JumpCode.GetCodeBuffer();

		// The data will sit in the beginning of the memory block
		PayloadData.SetBaseAddress(PayloadAddress);

		// The code will sit right after the data block
		CodeManager.SetupCodeAddresses(PayloadAddress + PayloadData.GetTotalDataSize());

		// Everything is now ready to prepare the code payload
		PrepareAssemblyCodePayload();
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

	EOperationStatus FuncHookProcessInjector::PrepareAssemblyCodePayload() noexcept
	{
		CodeManager.ModifyOperandsFor("RemoveProtection",
			{
				{TargetFunctionAddress},
				{static_cast<DWORD>(USED_JUMP_INSTRUCTION_SIZE)},
				{static_cast<DWORD>(PAGE_EXECUTE_READWRITE)},
				{PayloadData.GetDataLocationByName("OldCodeProtection")},
				{ProcessUtils.GetFunctionAddress("kernelbase!VirtualProtect")}

			}
		);

		CodeManager.ModifyOperandsFor("CopyOriginalFunction",
			{
				{TargetFunctionAddress},
				{PayloadData.GetDataLocationByName("TargetFunctionBackup")},
				{static_cast<DWORD>(USED_JUMP_INSTRUCTION_SIZE)},
				{ProcessUtils.GetFunctionAddress("ntdll!memcpy")}

			}
		);

		CodeManager.ModifyOperandsFor("FlushInstructionCache",
			{
				{ProcessUtils.GetFunctionAddress("kernelbase!GetCurrentProcess")},
				{TargetFunctionAddress},
				{static_cast<DWORD>(USED_JUMP_INSTRUCTION_SIZE)},
				{ProcessUtils.GetFunctionAddress("kernelbase!FlushInstructionCache")}

			}
			);

		CodeManager.ModifyOperandsFor("LoadInjectedDLL",
			{
				{PayloadData.GetDataLocationByName("DllPath")},
				{ProcessUtils.GetFunctionAddress("kernelbase!LoadLibraryA")}

			}
		);

		CodeManager.ModifyOperandsFor("JumpToOriginalFunction",
			{
				{ static_cast<DWORD>(AssemblyCode::CalculateRelativeJumpDisplacement(
				  CodeManager.GetCodeMemoryLocationFor("JumpToOriginalFunction"), TargetFunctionAddress)) }
			}
		);

		AppendBufferToBuffer(PayloadBuffer, CodeManager.GetAllCodeBuffer());

		return EOperationStatus::SUCCESS;
	}

	EOperationStatus FuncHookProcessInjector::PrepareDataPayload() noexcept
	{
		// First we write the path to the dll at the beginning of the payload address
		PayloadData.AddData("DllPath", DllToInject);
		
		// Read the function we want to hook so we could restore ( unhook ) it after our payload was executed
		PayloadData.AddData("TargetFunctionBackup", ProcessUtils.ReadBufferFromProcess(TargetFunctionAddress, USED_JUMP_INSTRUCTION_SIZE));

		// 
		PayloadData.AddData("OldCodeProtection", 0);

		AppendBufferToBuffer(PayloadBuffer, PayloadData.ConvertDataToBuffer());

		return EOperationStatus::SUCCESS;
	}
}

