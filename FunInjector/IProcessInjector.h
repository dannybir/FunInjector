#pragma once

#include "pch.h"
#include "ProcessInformationUtils.h"

namespace FunInjector
{
	class IProcessInjector
	{

	public:
		IProcessInjector( const DWORD ProcId, const std::string& DllName ) 
			: DllToInject( DllName ), ProcessId( ProcId )
		{}

		virtual ~IProcessInjector()
		{}

		// When the everything is prepared, initiates the injection process
		// Injection may be performed differently depending on the implementation of certain techniques
		virtual EOperationStatus InjectDll() = 0;	

		// Initialies all needed buffers and addresses to start the injection process
		virtual EOperationStatus PrepareForInjection() = 0;

	protected:
		// Initializes the ProcessUtils object by creating a process handle for it
		// and then performs initialization of it by invoking enumeration of modules
		// If this fails, at the moment, injection will fail as-well
		virtual EOperationStatus PrepareProcInfoUtils() = 0;

	protected:
		// Full path of the DLL we would like to inject to the target process
		std::string DllToInject;

		// PID of the target process, used for Handle creation
		DWORD ProcessId = 0;

		// A helper object which helps us to write/read/query information to/from the target process
		ProcessInformationUtils ProcessUtils;

		// Injection will not continue if this flag is false, will be set to true once PrepareForInjection has completed successefully
		bool IsPrepared = false;
	};
}


