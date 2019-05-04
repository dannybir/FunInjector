#pragma once

#include "IProcessInjector.h"
#include "AssemblyCodeManager.h"
#include "PayloadDataHolder.h"

namespace FunInjector
{
	// We hardcode this for now, should probably have a better way to define this
	constexpr auto USED_JUMP_INSTRUCTION_SIZE = 0x8;

	class FuncHookProcessInjector : public IProcessInjector
	{
	public:
		FuncHookProcessInjector(const DWORD ProcessId, const std::string& DllName, const std::string& FunctionName );
		virtual ~FuncHookProcessInjector();

		// When the everything is prepared, initiates the injection process
		// Done by writing all needed buffers to their correct locations
		virtual EOperationStatus InjectDll() noexcept override;
		
		// Initialies all needed buffers and addresses to start the injection process
		virtual EOperationStatus PrepareForInjection() noexcept override;

	protected:
		// Initializes the ProcessUtils object by creating a process handle for it
		// and then performs initialization of it by invoking enumeration of modules
		// If this fails, at the moment, injection will fail as-well
		virtual EOperationStatus PrepareProcInfoUtils() noexcept override;

	private:
		EOperationStatus PrepareAssemblyCodePayload() noexcept;
		EOperationStatus PrepareDataPayload() noexcept;

	private:
		// Name of the victim function we would hook to initiate the loading of our dll
		std::string TargetFunctionName;

		// Address of the function we would hook to start our injection
		DWORD64		TargetFunctionAddress;

		// Address in the remote process of the start of the payload buffer code
		DWORD64		PayloadAddress;

		//
		SIZE_T		TargetFunctionOverwriteSize;

		// Buffer for the jump instruction which will be used to hook the target function
		ByteBuffer	JmpHookBuffer;

		// This buffer will contain everything needed ( data + assembly code ) to be injected
		// into the remote process, will be written to PayloadAddress address in the remote process
		ByteBuffer	PayloadBuffer;

		//
		PayloadDataHolder PayloadData;

		//
		AssemblyCodeManager CodeManager;

	};

}

