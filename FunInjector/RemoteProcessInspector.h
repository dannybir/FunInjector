#pragma once

#include "ProcessModuleInspector.h"
#include "ProcessFunctionInspector.h"
#include "ProcessMemoryInspector.h"

namespace FunInjector::ProcessInspector
{
	class RemoteProcessInspector
	{
	public:
		RemoteProcessInspector();
		~RemoteProcessInspector();

		EOperationStatus InitializeInspectors(wil::shared_handle ProcessHandle) noexcept;

		inline const auto& GetProcessMemoryInspector() const
		{
			return ProcMemInspector;
		}

		inline const auto& GetProcessModuleInspector() const
		{
			return ProcModuleInspector;
		}

		inline const auto& GetProcessFunctionInspector() const
		{
			return ProcFuncInspector;
		}

		std::filesystem::path GetProcessPath() const noexcept;
		std::wstring		  GetProcessName() const noexcept;

		bool				  IsProcess64Bit() const noexcept;

	private:
		std::shared_ptr< ProcessMemoryInspector> ProcMemInspector;
		std::shared_ptr< ProcessModuleInspector> ProcModuleInspector;
		std::shared_ptr< ProcessFunctionInspector> ProcFuncInspector;
		std::shared_ptr< ProcessInformationInspector > ProcInfoInspector;

		wil::shared_handle ProcessHandle;
	};
}


