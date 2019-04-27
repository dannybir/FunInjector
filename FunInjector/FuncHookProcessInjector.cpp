
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
	}

	EOperationStatus FuncHookProcessInjector::PrepareForInjection() noexcept
	{
		if (PrepareProcInfoUtils() == EOperationStatus::FAIL)
		{
			return EOperationStatus::FAIL;
		}

		// Prepare the code manager, initiate it using the target process bitness so it could create correct assembly
		CodeManager = AssemblyCodeManager(ECodeBitnessMode::X64);

		// Generate assembly code which will be ultimately injected into the target process for execution
		

		/*
			Set up the jump instruction buffer which will jump to our payload code
		*/
		TargetFunctionAddress = ProcessUtils.GetFunctionAddress(TargetFunctionName);
		if (TargetFunctionAddress == 0)
		{
			return EOperationStatus::FAIL;
		}


		// Will insert needed data information into the payload buffer
		PrepareDataPayload();
		auto DataSize = PayloadData.GetTotalDataSize();

		// Set up the jmp to the payload code
		auto JumpCode = AssemblyCode::PrepareRelativeJump(TargetFunctionAddress, PayloadAddress + DataSize);
		TargetFunctionOverwriteSize = JumpCode.GetCodeSize();
		JmpHookBuffer = JumpCode.GetCodeBuffer();

		// Find some free memory and allocate big enough memory
		
		auto CodeSize = CodeManager.GetSizeByTypeList(PayloadCode);

		SIZE_T PayloadSize = DataSize + CodeSize;
		PayloadAddress = ProcessUtils.FindAndAllocateExecuteMemoryInProcess(PayloadSize + 0x50);
		if (PayloadAddress == 0)
		{
			return EOperationStatus::FAIL;
		}

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
				{static_cast<DWORD>(TargetFunctionOverwriteSize)},
				{static_cast<DWORD>(PAGE_EXECUTE_WRITECOPY)},
				{ProcessUtils.GetFunctionAddress("kernelbase!VirtualProtect")}

			}
		);

		CodeManager.ModifyOperandsFor("CopyOriginalFunction",
			{
				{TargetFunctionAddress},
				{PayloadData.GetDataLocationByName("TargetFunctionBackup")},
				{static_cast<DWORD>(TargetFunctionOverwriteSize)},
				{ProcessUtils.GetFunctionAddress("ntdll!memcpy")}

			}
		);

		CodeManager.ModifyOperandsFor("JumpToOriginalFunction",
			{
				{ static_cast<DWORD>(AssemblyCode::CalculateRelativeJumpDisplacement()) }
			});

		// We would like our return jump to jump back after executing all the code
		//auto ReturnJumpBuffer = JumpInstructions::GenerateRelativeJumpCode(PayloadAddress + PayloadSize - TargetFunctionOverwriteSize, TargetFunctionAddress);
		
		return EOperationStatus::SUCCESS;
	}

	EOperationStatus FuncHookProcessInjector::PrepareDataPayload() noexcept
	{
		// First we write the path to the dll at the beginning of the payload address
		PayloadData.AddData("DllPath", DllToInject);
		
		// Read the function we want to hook so we could restore ( unhook ) it after our payload was executed
		PayloadData.AddData("TargetFunctionBackup", ProcessUtils.ReadBufferFromProcess(TargetFunctionAddress, TargetFunctionOverwriteSize));

		return EOperationStatus::SUCCESS;
	}
}

