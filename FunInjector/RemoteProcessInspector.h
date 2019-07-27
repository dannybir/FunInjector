#pragma once

#include "ProcessModuleInspector.h"
#include "ProcessFunctionInspector.h"
#include "ProcessMemoryInspector.h"

namespace FunInjector::ProcessInspector
{
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
			ProcModuleInspector->LoadInformation();

			auto ProcFuncInspector = std::make_shared< ProcessFunctionInspector >(ProcessHandle);
			ProcFuncInspector->AttachMemoryInspector(ProcMemInspector);
			ProcFuncInspector->AttachModuleInspector(ProcModuleInspector);

			Inspectors = std::make_tuple(ProcInfoInspector, ProcMemInspector, ProcModuleInspector, ProcFuncInspector);

			HANDLE_EXCEPTION_END(EOperationStatus::FAIL);

			return EOperationStatus::SUCCESS;
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


