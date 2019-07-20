
#include "pch.h"
#include "FuncHookProcessInjector.h"

namespace FunInjector
{
	FuncHookProcessInjector::FuncHookProcessInjector( const DWORD ProcessId, const std::wstring& DllName, const std::wstring& FunctionName )
		: IProcessInjector( ProcessId, DllName ), TargetFunctionName(FunctionName)
	{
	}


	FuncHookProcessInjector::~FuncHookProcessInjector()
	{
	}

	EOperationStatus FuncHookProcessInjector::InjectDll() noexcept
	{
		// First write the payload
		if (ProcMemUtils.WriteBufferToProcess(PayloadBuffer, PayloadAddress, PayloadBuffer.size()) == EOperationStatus::FAIL)
		{
			return EOperationStatus::FAIL;
		}

		// Second, write the hook
		if (ProcMemUtils.WriteBufferToProcess(JmpHookBuffer, TargetFunctionAddress, JmpHookBuffer.size()) == EOperationStatus::FAIL)
		{
			return EOperationStatus::FAIL;
		}

		return EOperationStatus::SUCCESS;
	}

	EOperationStatus FuncHookProcessInjector::PrepareForInjection() noexcept
	{
		if (PrepareProcUtils() == EOperationStatus::FAIL)
		{
			return EOperationStatus::FAIL;
		}

		// Prepare the code manager, initiate it using the target process bitness so it could create correct assembly code
		CodeManager = AssemblyCodeManager(ECodeBitnessMode::X86);

		// Order is important here
		CodeManager.AddAssemblyCode(L"PushRegisters", ECodeType::PUSH_REGISTERS);
		CodeManager.AddAssemblyCode(L"RemoveProtection", ECodeType::VIRTUAL_PROTECT);
		CodeManager.AddAssemblyCode(L"CopyOriginalFunction", ECodeType::MEMCOPY);
		CodeManager.AddAssemblyCode(L"FlushInstructionCache", ECodeType::FLUSH_INSTRUCTION);
		CodeManager.AddAssemblyCode(L"LoadInjectedDLL", ECodeType::LOAD_DLL);
		CodeManager.AddAssemblyCode(L"PopRegisters", ECodeType::POP_REGISTERS);
		//

		CodeManager.AddAssemblyCode(L"JumpToOriginalFunction", ECodeType::RELATIVE_JUMP);

		TargetFunctionAddress = ProcessInfoUtils.GetFunctionAddress(TargetFunctionName);
		if (TargetFunctionAddress == 0)
		{
			return EOperationStatus::FAIL;
		}

		PrepareDataPayload();

		// Find some free memory and allocate big enough memory
		SIZE_T PayloadSize = PayloadData.GetTotalDataSize() + CodeManager.GetTotalCodeSize();
		PayloadAddress = ProcMemUtils.FindAndAllocateExecuteMemoryInProcess(ProcessInfoUtils.GetModuleAddress(L"ntdll.dll"), PayloadSize + 0x50);
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

	EOperationStatus FuncHookProcessInjector::PrepareProcUtils() noexcept
	{
		auto ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessId);
		if (ProcessHandle == nullptr)
		{
			LOG_ERROR << L"Failed to open process handle for process id: " << ProcessId;
			return EOperationStatus::FAIL;
		}

		ProcMemUtils = FunInjector::ProcessUtils::ProcessMemoryUtils(ProcessHandle);
		ProcessInfoUtils = FunInjector::ProcessUtils::ProcessInformationUtils(ProcessHandle, false);

		return ProcessInfoUtils.EnumerateProcessModules();
	}

	EOperationStatus FuncHookProcessInjector::PrepareAssemblyCodePayload() noexcept
	{
		CodeManager.ModifyOperandsFor(L"RemoveProtection",
			{
				// lpflOldProtect
				{CodeManager.TranslateOperandSize(PayloadData.GetDataLocationByName(L"OldCodeProtection"))},

				// NewProtect
				{static_cast<DWORD>(PAGE_EXECUTE_READWRITE)},

				// Code size
				{static_cast<DWORD>(USED_JUMP_INSTRUCTION_SIZE)},

				// Target Address
				{CodeManager.TranslateOperandSize( TargetFunctionAddress )},

				// Function pointer
				{CodeManager.TranslateOperandSize(ProcessInfoUtils.GetFunctionAddress(L"kernelbase!VirtualProtect"))}
			}
		);

		CodeManager.ModifyOperandsFor(L"CopyOriginalFunction",
			{
				// Copy size
				{static_cast<DWORD>(USED_JUMP_INSTRUCTION_SIZE)},

				// Source
				{CodeManager.TranslateOperandSize(PayloadData.GetDataLocationByName(L"TargetFunctionBackup"))},

				// Destination
				{CodeManager.TranslateOperandSize(TargetFunctionAddress)},
				
				// Function pointer
				{CodeManager.TranslateOperandSize(ProcessInfoUtils.GetFunctionAddress(L"ntdll!memcpy"))}

			}
		);

		CodeManager.ModifyOperandsFor(L"FlushInstructionCache",
			{
				{CodeManager.TranslateOperandSize(ProcessInfoUtils.GetFunctionAddress(L"kernelbase!GetCurrentProcess"))},

				// Size of code to flush
				{static_cast<DWORD>(USED_JUMP_INSTRUCTION_SIZE)},

				// Target of flush
				{CodeManager.TranslateOperandSize(TargetFunctionAddress)},
				
				{CodeManager.TranslateOperandSize(ProcessInfoUtils.GetFunctionAddress(L"kernelbase!FlushInstructionCache"))}

			}
			);

		CodeManager.ModifyOperandsFor(L"LoadInjectedDLL",
			{
				{CodeManager.TranslateOperandSize(PayloadData.GetDataLocationByName(L"DllPath"))},
				{CodeManager.TranslateOperandSize(ProcessInfoUtils.GetFunctionAddress(L"kernelbase!LoadLibraryW"))}

			}
		);

		CodeManager.ModifyOperandsFor(L"JumpToOriginalFunction",
			{
				{ static_cast<DWORD>(AssemblyCode::CalculateRelativeJumpDisplacement(
				  CodeManager.GetCodeMemoryLocationFor(L"JumpToOriginalFunction"), TargetFunctionAddress)) }
			}
		);

		AppendBufferToBuffer(PayloadBuffer, CodeManager.GetAllCodeBuffer());

		return EOperationStatus::SUCCESS;
	}

	EOperationStatus FuncHookProcessInjector::PrepareDataPayload() noexcept
	{
		// First we write the path to the dll at the beginning of the payload address
		PayloadData.AddData(L"DllPath", DllToInject);
		
		// Read the function we want to hook so we could restore ( unhook ) it after our payload was executed
		PayloadData.AddData(L"TargetFunctionBackup", ProcMemUtils.ReadBufferFromProcess(TargetFunctionAddress, USED_JUMP_INSTRUCTION_SIZE));

		// 
		PayloadData.AddData(L"OldCodeProtection", 0);

		AppendBufferToBuffer(PayloadBuffer, PayloadData.ConvertDataToBuffer());

		return EOperationStatus::SUCCESS;
	}
}

