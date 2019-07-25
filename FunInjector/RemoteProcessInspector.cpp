#include "pch.h"
#include "RemoteProcessInspector.h"

namespace FunInjector::ProcessInspector
{
	RemoteProcessInspector::RemoteProcessInspector()
	{
	}


	RemoteProcessInspector::~RemoteProcessInspector()
	{
	}

	EOperationStatus RemoteProcessInspector::InitializeInspectors(wil::shared_handle ProcessHandle) noexcept
	{
		ProcInfoInspector = std::make_shared< ProcessInformationInspector >(ProcessHandle);
		ProcInfoInspector->RetrieveInformation();

		ProcMemInspector = std::make_shared< ProcessMemoryInspector >(ProcessHandle);
		
		ProcModuleInspector = std::make_shared< ProcessModuleInspector >(ProcessHandle);
		ProcModuleInspector->AttachMemoryInspector(ProcMemInspector);
		ProcModuleInspector->AttachInfoInspector(ProcInfoInspector);
		ProcModuleInspector->LoadInformation();

		ProcFuncInspector = std::make_shared< ProcessFunctionInspector >(ProcessHandle);
		ProcFuncInspector->AttachMemoryInspector(ProcMemInspector);
		ProcFuncInspector->AttachModuleInspector(ProcModuleInspector);

		return EOperationStatus::SUCCESS;
	}
}