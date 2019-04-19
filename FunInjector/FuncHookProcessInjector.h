#pragma once

#include "IProcessInjector.h"

namespace FunInjector
{
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
		EOperationStatus CreateInjectionCodeBuffer() noexcept;

	private:
		// Name of the victim function we would hook to initiate the loading of our dll
		std::string TargetFunctionName;

		// Address of the function we would hook to start our injection
		DWORD64		TargetFunctionAddress;

		// Address in the remote process of the start of the payload buffer code
		DWORD64		PayloadAddress;

		// Assembly code which will be executed on the remote process to load our DLL
		ByteBuffer	PayloadBuffer;

		// Buffer for the jump instruction which will be used to hook the target function
		ByteBuffer	JmpHookBuffer;

		// This buffer holds the instructions that are overwritten by the jmp
		// We need them so that we can restore the function to normal once injection ends
		ByteBuffer	TargetFunctionStartBackup;

	};

}

