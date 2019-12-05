#include "pch.h"
#include "ProcessInformationInspector.h"


namespace FunInjector::ProcessInspector
{
	ProcessInformationInspector::ProcessInformationInspector(wil::shared_handle ProcHandle) : ProcessHandle( ProcHandle )
	{
	}

	EOperationStatus ProcessInformationInspector::RetrieveInformation() noexcept
	{
		IsProcess64Bit = DetermineIsProcess64Bit();
		return EOperationStatus::SUCCESS;
	}

	bool ProcessInformationInspector::DetermineIsProcess64Bit() const
	{
		// First check the OS bitness, if the bitness is 32bit, the process must be 32bit
		SYSTEM_INFO SysInfo{ 0 };
		GetNativeSystemInfo(&SysInfo);

		if (SysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
		{
			// This is a 32bit OS
			return false;
		}
		
		// This is a 64bit OS, so lets check if the process is Wow64
		BOOL IsWow64 = false;
		if (!IsWow64Process(ProcessHandle.get(), &IsWow64))
		{
			// If the function fails, it cannot be a wow64 process
			return false;
		}

		if (IsWow64)
		{
			// Process is Wow64, so its a 32bit process in a 64bit system
			return false;
		}
		
		return true;
	}
}





