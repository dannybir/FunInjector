#pragma once

#include "ProcessInjectorBase.h"
#include "AssemblyCodeManager.h"
#include "PayloadDataHolder.h"
#include "RemoteProcessInspector.h"

namespace FunInjector
{
	using namespace FunInjector::ProcessInspector;

	// Tests have shown that 15 bytes should be more than enough to backup
	// the target function
	constexpr auto TARGET_FUNCTION_BACKUP_SIZE = 0xF;

	class FuncHookProcessInjector : public ProcessInjectorBase
	{
	public:
		FuncHookProcessInjector(const DWORD ProcessId, 
			const std::wstring& DllPath, 
			const std::string& TargetFuncName,
			const std::string& TargetModName);

		FuncHookProcessInjector( wil::shared_handle ProcessHandle, 
			const std::wstring& DllPath, 
			const std::string& TargetFuncName,
			const std::string& TargetModName);

		virtual ~FuncHookProcessInjector();

		// When the everything is prepared, initiates the injection process
		// Done by writing all needed buffers to their correct locations
		virtual EOperationStatus InjectDll() noexcept override;
		
		// Initialies all needed buffers and addresses to start the injection process
		virtual EOperationStatus PrepareForInjection() noexcept override;

	private:
		// Initializes the ProcessUtils object by creating a process handle for it
		// and then performs initialization of it by invoking enumeration of modules
		// If this fails, at the moment, injection will fail as-well
		void PrepareProcessInspector();

	private:
		void PrepareAssemblyCodePayload();
		void PrepareDataPayload();

	private:
		// Name of the victim function we would hook to initiate the loading of our dll
		std::string TargetFunctionName;

		// 
		std::string TargetModuleName;

		// Address of the function we would hook to start our injection
		DWORD64		TargetFunctionAddress;

		// Address in the remote process of the start of the payload buffer code
		DWORD64		PayloadAddress;

		// Buffer for the jump instruction which will be used to hook the target function
		ByteBuffer	JmpHookBuffer;

		// This buffer will contain everything needed ( data + assembly code ) to be injected
		// into the remote process, will be written to PayloadAddress address in the remote process
		ByteBuffer	PayloadBuffer;

		// Contains and manages data objects that the payload assembly may need to use
		PayloadDataHolder PayloadData;

		// Contains and manages all assembly code that is part of the payload
		AssemblyCodeManager CodeManager;

		// This remote proc inspector is used to query,read,write data to the process
		RemoteProcessInspector< ProcessInformationInspector, 
			ProcessMemoryInspector, ProcessModuleInspector, ProcessFunctionInspector> ProcessInspector;

	};

}
// This is just to have shorter code, convinience?
#define GET_INSPECTOR(Type) ProcessInspector.GetInspectorByType<Type>()

