
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

		ProcessInformationInspector CurrentProcessInspector = ProcessInformationInspector(wil::shared_handle(GetCurrentProcess()));
		CurrentProcessInspector.RetrieveInformation();

		// Check whether the injection can be performed by the current host process
		if (GET_INSPECTOR(ProcessInformationInspector)->IsProcess64Bit
			&&
			!CurrentProcessInspector.IsProcess64Bit)
		{
			// Current host process is a 32bit process
			// Target process is a 64 bit process
			// As a result, we must use a 64bit host process to perform the injection
			LOG_WARNING << L"Must switch to use a 64bit host of the injector, injection target is a 64bit, current host is 32bit";
			return EOperationStatus::USE_64_HOST;
		}

		// Prepare the code manager, initiate it using the target process bitness so it could create correct assembly code
		CodeManager = AssemblyCodeManager( GET_INSPECTOR(ProcessInformationInspector)->IsProcess64Bit ? ECodeBitnessMode::X64 : ECodeBitnessMode::X86 );

		// Order is important here, each step is explained as follows:

		// We must preserve all registers so that once we return to the target function
		// It could continue normally
		CodeManager.AddAssemblyCode(L"PushRegisters", ECodeType::PUSH_REGISTERS);

		// Restore the original target function beginning, this set of instructions use memcpy to do that
		CodeManager.AddAssemblyCode(L"CopyOriginalFunction", ECodeType::MEMCOPY);

		// This flushes the CPU instruction cache in the area of the restored code
		CodeManager.AddAssemblyCode(L"FlushInstructionCache", ECodeType::FLUSH_INSTRUCTION);

		// Restores the protection to the code we changed
		// Don't restore protection for now, it dosent work well in 64bit
		// And not really required for the injection to be successeful
		//CodeManager.AddAssemblyCode(L"RestoreProtection", ECodeType::VIRTUAL_PROTECT);

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
			ProcessInspector.GetInspectorByType<ProcessModuleInspector>()->GetModuleAddress("ntdll.dll"), PayloadSize + 0x50);

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

		// We only need to get the target module really for the injection
		GET_INSPECTOR(ProcessModuleInspector)->LoadInformation(std::wstring(TargetModuleName.begin(), TargetModuleName.end()));
	}

	void FuncHookProcessInjector::PrepareAssemblyCodePayload()
	{
		// Remove protection from the function prologue that we would like to hook
		// We would need to restore this protection when the hook self-deletes
		DWORD OriginalProtect = 0;
		if (!VirtualProtectEx(ProcessHandle.get(),
			reinterpret_cast<PVOID>(TargetFunctionAddress), TARGET_FUNCTION_BACKUP_SIZE, PAGE_EXECUTE_READWRITE, &OriginalProtect))
		{
			THROW_EXCEPTION_FORMATTED_MESSAGE( L"Failed to change protection of address: " << std::hex << TargetFunctionAddress
				<< L", to: PAGE_EXECUTE_READWRITE, injection won't be possible" );
		}

		CodeManager.ModifyOperandsFor(L"RestoreProtection",
			{
				// lpflOldProtect
				{CodeManager.TranslateOperandSize(PayloadData.GetDataLocationByName(L"OldCodeProtection"))},

				// NewProtect
				{OriginalProtect},

				// Code size
				{CodeManager.TranslateOperandSize(PayloadData.GetDataLocationByName(L"CodeRegionSize"))},

				// Target Address
				{CodeManager.TranslateOperandSize(PayloadData.GetDataLocationByName(L"TargetFunctionAddress"))},

				// Function pointer
				{CodeManager.TranslateOperandSize(
				GET_INSPECTOR(ProcessFunctionInspector)->GetRemoteFunctionAddress("NtProtectVirtualMemory","ntdll.dll"))}
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
				GET_INSPECTOR(ProcessFunctionInspector)->GetRemoteFunctionAddress("memcpy","ntdll.dll"))}

			}
		);

		CodeManager.ModifyOperandsFor(L"FlushInstructionCache",
			{
				// Size of code to flush
				{static_cast<DWORD>(TARGET_FUNCTION_BACKUP_SIZE)},

				// Target of flush
				{CodeManager.TranslateOperandSize(TargetFunctionAddress)},
				
				{CodeManager.TranslateOperandSize(
					GET_INSPECTOR(ProcessFunctionInspector)->GetRemoteFunctionAddress("NtFlushInstructionCache","ntdll.dll"))}

			}
			);

		CodeManager.ModifyOperandsFor(L"LoadInjectedDLL",
			{
				{CodeManager.TranslateOperandSize(PayloadData.GetDataLocationByName(L"DllPath"))},
				{CodeManager.TranslateOperandSize(GET_INSPECTOR(ProcessFunctionInspector)->GetRemoteFunctionAddress("RtlInitUnicodeString","ntdll.dll"))},

				{CodeManager.TranslateOperandSize(PayloadData.GetDataLocationByName(L"InjectedModuleAddresAfterLoad"))},
				{CodeManager.TranslateOperandSize(static_cast<DWORD64>(0))},			
				{static_cast<DWORD>(0)},
				{CodeManager.TranslateOperandSize( GET_INSPECTOR(ProcessFunctionInspector)->GetRemoteFunctionAddress("LdrLoadDll","ntdll.dll") )}
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

		// Used for the removal of code protection
		PayloadData.AddData(L"OldCodeProtection", 0);
		PayloadData.AddData(L"CodeRegionSize", TARGET_FUNCTION_BACKUP_SIZE);

		PayloadData.AddData(L"TargetFunctionAddress", 
			((GET_INSPECTOR(ProcessInformationInspector)->IsProcess64Bit)
				? TargetFunctionAddress : static_cast<DWORD>(TargetFunctionAddress)));

		// Used for Dll loading
		PayloadData.AddData(L"InjectedModuleAddresAfterLoad", 0);

		AppendBufferToBuffer(PayloadBuffer, PayloadData.ConvertDataToBuffer());
	}
}

