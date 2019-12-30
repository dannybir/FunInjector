#pragma once

#include "ProcessModuleInspector.h"
#include "ProcessFunctionInspector.h"
#include "ProcessMemoryInspector.h"

namespace FunInjector::ProcessInspector
{
	// An aggregetor class containing all possible inspectors
	// The injector would usually need to use all the inspectors
	// Also, some inspectors depends on other to exist
	// A RemoteProcessInspector is unique up to the process handle being used
	template <typename ... InspectorTypes >
	class RemoteProcessInspector
	{
	public:
		EOperationStatus InitializeInspectors(wil::shared_handle ProcessHandle) noexcept
		{
			HANDLE_EXCEPTION_BEGIN;

			auto ProcInfoInspector = std::make_shared< ProcessInformationInspector >(ProcessHandle);
			ProcInfoInspector->RetrieveInformation();

			auto ProcMemInspector = std::make_shared< ProcessMemoryInspector >(ProcessHandle);

			auto ProcModuleInspector = std::make_shared< ProcessModuleInspector >(ProcessHandle);
			ProcModuleInspector->AttachMemoryInspector(ProcMemInspector);
			ProcModuleInspector->AttachInfoInspector(ProcInfoInspector);

			auto ProcFuncInspector = std::make_shared< ProcessFunctionInspector >(ProcessHandle);
			ProcFuncInspector->AttachMemoryInspector(ProcMemInspector);
			ProcFuncInspector->AttachModuleInspector(ProcModuleInspector);

			Inspectors = std::make_tuple(ProcInfoInspector, ProcMemInspector, ProcModuleInspector, ProcFuncInspector);

			LOG_DEBUG << L"Successefuly created all process inspectors, they are now ready to use for handle: "
				<< std::hex << ProcessHandle.get();
			return EOperationStatus::SUCCESS;

			HANDLE_EXCEPTION_END_RET(EOperationStatus::FAIL);
		}

		template <class InspectorType>
		decltype(auto) GetInspectorByType()
		{
			return std::get<std::shared_ptr<std::decay_t<InspectorType>>>(Inspectors);
		}

	private:
		std::tuple<std::shared_ptr<InspectorTypes>...> Inspectors;
	};
}



