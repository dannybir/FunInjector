
#include "pch.h"
#include "FuncHookProcessInjector.h"
#include "AssemblyCodeGenerator.h"

namespace FunInjector
{
	FuncHookProcessInjector::FuncHookProcessInjector( const DWORD ProcessId, const std::string& DllName, const std::string& FunctionName )
		: IProcessInjector( ProcessId, DllName ), TargetFunctionName(FunctionName)
	{
		JmpInstructionDefaultSize = static_cast<SIZE_T>(JumpInstructions::JumpInstructionSizes::RELATIVE_JUMP);
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
	}

	EOperationStatus FuncHookProcessInjector::PrepareForInjection() noexcept
	{
		// 1. Prepare all buffers ( Data + Code ) to know their size
		// 2. Create allocated memory in target process with Data+Code+Constant size
		// 3. Create a jump hook buffer which will jump to allocated memory + data
		// 4. Update code operands with memory locations of the data


		if (PrepareProcInfoUtils() == EOperationStatus::FAIL)
		{
			return EOperationStatus::FAIL;
		}

		TargetFunctionAddress = ProcessUtils.GetFunctionAddress(TargetFunctionName);
		if (TargetFunctionAddress == 0)
		{
			return EOperationStatus::FAIL;
		}

		// Generate assembly code which will be ultimately injected into the target process for execution
		VirtualProtectCode = GenerateVirtualProtectCode64();
		RestoreFunctionMemoryCode = GenerateMemCpyCode64();

		// Read the function we want to hook so we could restore ( unhook ) it after our payload was executed
		TargetFunctionStartBackup = ProcessUtils.ReadBufferFromProcess(TargetFunctionAddress, JmpInstructionDefaultSize);

		// Find some free memory and allocate big enough memory
		auto DataSize = DllToInject.size() + 1 + TargetFunctionStartBackup.size();
		auto CodeSize = VirtualProtectCode.GetCodeSize() +
						RestoreFunctionMemoryCode.GetCodeSize() +
						JmpInstructionDefaultSize;

		SIZE_T PayloadSize = DataSize + CodeSize;
		PayloadAddress = ProcessUtils.FindAndAllocateExecuteMemoryInProcess(PayloadSize + 0x50);
		if (PayloadAddress == 0)
		{
			return EOperationStatus::FAIL;
		}

		// Will insert needed data information into the payload buffer
		PrepareDataPayload();

		// We would like our hook to jump into the beginning of the code section
		JmpHookBuffer = JumpInstructions::GenerateRelativeJumpCode(TargetFunctionAddress, PayloadAddress + DataSize);

		// Get the payload buffer populated with the code buffers
		PrepareAssemblyCodePayload();

		// We would like our return jump to jump back after executing all the code
		auto ReturnJumpBuffer = JumpInstructions::GenerateRelativeJumpCode(PayloadAddress + PayloadSize - JmpInstructionDefaultSize, TargetFunctionAddress);
		AppendBufferToBuffer(PayloadBuffer, ReturnJumpBuffer);

		// At this point, our PayloadBuffer should be ready with everything needed
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
		VirtualProtectCode.ModifyOperandsInOrder(
			{
				{TargetFunctionAddress},
				{static_cast<DWORD>(JumpInstructions::JumpInstructionSizes::RELATIVE_JUMP)},
				{static_cast<DWORD>(PAGE_EXECUTE_WRITECOPY)},
				{ProcessUtils.GetFunctionAddress("kernelbase!VirtualProtect")}

			}
		);
		AppendBufferToBuffer(PayloadBuffer, VirtualProtectCode.GetCodeBuffer());

		RestoreFunctionMemoryCode.ModifyOperandsInOrder(
			{
				{TargetFunctionAddress},
				{PayloadAddress + DllToInject.size() + 1},
				{static_cast<DWORD>(JumpInstructions::JumpInstructionSizes::RELATIVE_JUMP)},
				{ProcessUtils.GetFunctionAddress("ntdll!memcpy")}

			}
		);
		AppendBufferToBuffer(PayloadBuffer, RestoreFunctionMemoryCode.GetCodeBuffer());
		
		return EOperationStatus::SUCCESS;
	}

	EOperationStatus FuncHookProcessInjector::PrepareDataPayload() noexcept
	{
		// First we write the path to the dll at the beginning of the payload address
		ByteBuffer DllPathBuffer(DllToInject.begin(), DllToInject.end());
		DllPathBuffer.push_back('\0');
		AppendBufferToBuffer(PayloadBuffer, DllPathBuffer);

		// Now the first bytes of the function we hooked
		AppendBufferToBuffer(PayloadBuffer, TargetFunctionStartBackup);

		return EOperationStatus::SUCCESS;
	}
}

