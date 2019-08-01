#pragma once

#include "pch.h"
#include "ProcessUtils.h"

namespace FunInjector
{
	class IProcessInjector
	{

	public:
		IProcessInjector( const DWORD ProcId, const std::wstring& DllPath ) 
			: DllToInject(DllPath), ProcessId( ProcId )
		{}

		IProcessInjector(wil::shared_handle ProcHandle, const std::wstring& DllPath)
			: DllToInject(DllPath), ProcessHandle(ProcHandle)
		{}

		virtual ~IProcessInjector()
		{}

		// When the everything is prepared, initiates the injection process
		// Injection may be performed differently depending on the implementation of certain techniques
		virtual EOperationStatus InjectDll() = 0;	

		// Initialies all needed buffers and addresses to start the injection process
		virtual EOperationStatus PrepareForInjection() = 0;

	protected:
		// Full path of the DLL we would like to inject to the target process
		std::wstring DllToInject;

		// PID of the target process, used for Handle creation
		DWORD ProcessId = 0;

		// Handle to the process we want to inject
		wil::shared_handle ProcessHandle;

		// Injection will not continue if this flag is false, will be set to true once PrepareForInjection has completed successefully
		bool IsPrepared = false;
	};
}


