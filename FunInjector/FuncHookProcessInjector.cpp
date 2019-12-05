
#include "pch.h"
#include "FuncHookProcessInjector.h"

namespace FunInjector
{
	using namespace ExceptionHandler;

	FuncHookProcessInjector::FuncHookProcessInjector(const DWORD ProcessId, const std::wstring& DllPath, const std::string& TargetFuncName,
		const std::string& TargetModName)
		: ProcessInjectorBase(ProcessId, DllPath), TargetFunctionName(TargetFuncName), TargetModuleName(TargetModName)
	{}

	FuncHookProcessInjector::FuncHookProcessInjector( wil::shared_handle ProcessHandle, const std::wstring& DllPath, const std::string& TargetFuncName,
		const std::string& TargetModName)
		: ProcessInjectorBase(ProcessHandle, DllPath), TargetFunctionName(TargetFuncName), TargetModuleName(TargetModName)
	{}

	FuncHookProcessInjector::~FuncHookProcessInjector()
	{
	}

	EOperationStatus FuncHookProcessInjector::InjectDll() noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		// First write the payload
		if (GET_INSPECTOR(ProcessMemoryInspector)->WriteBufferToProcess(PayloadBuffer, PayloadAddress, PayloadBuffer.size()) 
			== EOperationStatus::FAIL)
		{
			LOG_ERROR << L"There was an error while writing the injection payload to the process, the injection will fail";
			return EOperationStatus::FAIL;
		}

		// Second, write the hook
		if (GET_INSPECTOR(ProcessMemoryInspector)->WriteBufferToProcess(JmpHookBuffer, TargetFunctionAddress, JmpHookBuffer.size()) 
			== EOperationStatus::FAIL)
		{
			LOG_ERROR << L"There was an error while writing the jump hook on the target victim function, the injection will fail";
			return EOperationStatus::FAIL;
		}

		LOG_DEBUG << L"All injection data was successefuly written to the target process, injection should be succeseful";

		HANDLE_EXCEPTION_END;
		return EOperationStatus::SUCCESS;
	}

	EOperationStatus FuncHookProcessInjector::PrepareForInjection() noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		PrepareProcessInspector();

		// Prepare the code manager, initiate it using the target process bitness so it could create correct assembly code
		CodeManager = AssemblyCodeManager( GET_INSPECTOR(ProcessInformationInspector)->IsProcess64Bit ? ECodeBitnessMode::X64 : ECodeBitnessMode::X86 );

		// Order is important here, each step is explained as follows:

		// We must preserve all registers so that once we return to the target function
		// It could continue normally
		CodeManager.AddAssemblyCode(L"PushRegisters", ECodeType::PUSH_REGISTERS);

		// Must remove protection from the target function beginning so we could overwrite our jump
		CodeManager.AddAssemblyCode(L"RemoveProtection", ECodeType::VIRTUAL_PROTECT);

		// Restore the original target function beginning, this set of instructions use memcpy to do that
		CodeManager.AddAssemblyCode(L"CopyOriginalFunction", ECodeType::MEMCOPY);

		// This flushes the CPU instruction cache in the area of the restored code
		CodeManager.AddAssemblyCode(L"FlushInstructionCache", ECodeType::FLUSH_INSTRUCTION);

		// This simply calls LoadLibrary to finally load the DLL we want to inject
		// There is no check to see if the DLL was loaded or not ( For now? )
		CodeManager.AddAssemblyCode(L"LoadInjectedDLL", ECodeType::LOAD_DLL);

		// Restore all the registers to their previous values, so target function could continue
		// Once we jump back to it
		CodeManager.AddAssemblyCode(L"PopRegisters", ECodeType::POP_REGISTERS);

		// Will jump to the target function which is now restored, it will continue running normally
		// Almost as though nothing happened :)
		CodeManager.AddAssemblyCode(L"JumpToOriginalFunction", ECodeType::RELATIVE_JUMP);

		TargetFunctionAddress = GET_INSPECTOR(ProcessFunctionInspector)->GetRemoteFunctionAddress(TargetFunctionName, TargetModuleName);
		if (TargetFunctionAddress == 0)
		{
			LOG_ERROR << L"Failed to retrieve the address of the target function: " << TargetFunctionName;
			return EOperationStatus::FAIL;
		}

		// Prepare the needed data in order to execute the injection
		PrepareDataPayload();

		// Find some free memory and allocate big enough space
		// We need some free area to put our injected assembly and data that the code will use
		SIZE_T PayloadSize = PayloadData.GetTotalDataSize() + CodeManager.GetTotalCodeSize();
		PayloadAddress = ProcessInspector.GetInspectorByType<ProcessMemoryInspector>()->FindAndAllocateExecuteMemoryInProcess(
			ProcessInspector.GetInspectorByType<ProcessModuleInspector>()->GetModuleAddress("ntdll"), PayloadSize + 0x50);

		if (PayloadAddress == 0)
		{
			LOG_ERROR << L"Failed to find a large enough space in the target process, tried to find: " 
				<< PayloadSize << L" continues free bytes";
			return EOperationStatus::FAIL;
		}

		// Set up the jmp to the payload code, we need to hook the target function so it jumps to our evil injection code
		auto JumpCode = AssemblyCode::PrepareRelativeJump(TargetFunctionAddress, PayloadAddress + PayloadData.GetTotalDataSize());
		JmpHookBuffer = JumpCode.GetCodeBuffer();

		// The data will sit in the beginning of the memory block
		PayloadData.SetBaseAddress(PayloadAddress);

		// The code will sit right after the data block
		CodeManager.SetupCodeAddresses(PayloadAddress + PayloadData.GetTotalDataSize());

		// Everything is now ready to prepare the code payload
		PrepareAssemblyCodePayload();

		HANDLE_EXCEPTION_END_RET( EOperationStatus::FAIL );

		LOG_DEBUG << L"Finished preparing the assembly code, the payload data and the jump hook, now ready for injection";
		return EOperationStatus::SUCCESS;
	}

	void FuncHookProcessInjector::PrepareProcessInspector()
	{
		if (!ProcessHandle)
		{
			ProcessHandle = wil::shared_handle(OpenProcess(PROCESS_ALL_ACCESS, false, ProcessId));
		}
			
		if (!ProcessHandle)
		{
			THROW_EXCEPTION_FORMATTED_MESSAGE( "Failed to open process handle for process id: " << ProcessId );
		}

		ProcessInspector.InitializeInspectors(ProcessHandle);
	}

	void FuncHookProcessInjector::PrepareAssemblyCodePayload()
	{
		CodeManager.ModifyOperandsFor(L"RemoveProtection",
			{
				// lpflOldProtect
				{CodeManager.TranslateOperandSize(PayloadData.GetDataLocationByName(L"OldCodeProtection"))},

				// NewProtect
				{static_cast<DWORD>(PAGE_EXECUTE_READWRITE)},

				// Code size
				{static_cast<DWORD>(TARGET_FUNCTION_BACKUP_SIZE)},

				// Target Address
				{CodeManager.TranslateOperandSize( TargetFunctionAddress )},

				// Function pointer
				{CodeManager.TranslateOperandSize(
				GET_INSPECTOR(ProcessFunctionInspector)->GetRemoteFunctionAddress("VirtualProtect","kernelbase"))}
			}
		);

		CodeManager.ModifyOperandsFor(L"CopyOriginalFunction",
			{
				// Copy size
				{static_cast<DWORD>(TARGET_FUNCTION_BACKUP_SIZE)},

				// Source
				{CodeManager.TranslateOperandSize(PayloadData.GetDataLocationByName(L"TargetFunctionBackup"))},

				// Destination
				{CodeManager.TranslateOperandSize(TargetFunctionAddress)},
				
				// Function pointer
				{CodeManager.TranslateOperandSize(
				GET_INSPECTOR(ProcessFunctionInspector)->GetRemoteFunctionAddress("memcpy","ntdll"))}

			}
		);

		CodeManager.ModifyOperandsFor(L"FlushInstructionCache",
			{
				{CodeManager.TranslateOperandSize(
				GET_INSPECTOR(ProcessFunctionInspector)->GetRemoteFunctionAddress("GetCurrentProcess","kernelbase"))},

				// Size of code to flush
				{static_cast<DWORD>(TARGET_FUNCTION_BACKUP_SIZE)},

				// Target of flush
				{CodeManager.TranslateOperandSize(TargetFunctionAddress)},
				
				{CodeManager.TranslateOperandSize(
					GET_INSPECTOR(ProcessFunctionInspector)->GetRemoteFunctionAddress("FlushInstructionCache","kernelbase"))}

			}
			);

		CodeManager.ModifyOperandsFor(L"LoadInjectedDLL",
			{
				{CodeManager.TranslateOperandSize(PayloadData.GetDataLocationByName(L"DllPath"))},
				{CodeManager.TranslateOperandSize(
				GET_INSPECTOR(ProcessFunctionInspector)->GetRemoteFunctionAddress("LoadLibraryW","kernelbase"))}

			}
		);

		CodeManager.ModifyOperandsFor(L"JumpToOriginalFunction",
			{
				{ static_cast<DWORD>(AssemblyCode::CalculateRelativeJumpDisplacement(
				  CodeManager.GetCodeMemoryLocationFor(L"JumpToOriginalFunction"), TargetFunctionAddress)) }
			}
		);

		AppendBufferToBuffer(PayloadBuffer, CodeManager.GetAllCodeBuffer());
	}

	void FuncHookProcessInjector::PrepareDataPayload()
	{
		// First we write the path to the dll at the beginning of the payload address
		PayloadData.AddData(L"DllPath", DllToInject);
		
		// Read the function we want to hook so we could restore ( unhook ) it after our payload was executed
		PayloadData.AddData(L"TargetFunctionBackup", 
			GET_INSPECTOR(ProcessMemoryInspector)->ReadBufferFromProcess(TargetFunctionAddress, TARGET_FUNCTION_BACKUP_SIZE));

		// 
		PayloadData.AddData(L"OldCodeProtection", 0);

		AppendBufferToBuffer(PayloadBuffer, PayloadData.ConvertDataToBuffer());
	}
}

