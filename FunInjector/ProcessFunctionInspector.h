#pragma once

#include "pch.h"
#include "ProcessMemoryInspector.h"
#include "ProcessModuleInspector.h"

namespace FunInjector::ProcessInspector
{
	class ProcessFunctionInspector
	{
	public:
		ProcessFunctionInspector(wil::shared_handle ProcHandle);

		DWORD64 GetRemoteFunctionAddress(const std::string_view FunctionName, const std::wstring_view ModuleName);

		inline void AttachMemoryInspector(std::shared_ptr< ProcessMemoryInspector > MemInspector)
		{
			ProcMemInspector = MemInspector;
		}

		inline void AttachModuleInspector(std::shared_ptr< ProcessModuleInspector > ModuleInspector)
		{
			ProcModuleInspector = ModuleInspector;
		}

	private:
		DWORD64 GetFunctionAddress(const std::string_view FunctionName, DWORD64 ModuleBaseAddress, ByteBuffer ModuleBuffer) const;
		ByteBuffer GetBufferOfModule(const std::wstring& ModuleName) const;


	private:
		std::shared_ptr< ProcessMemoryInspector> ProcMemInspector;
		std::shared_ptr< ProcessModuleInspector> ProcModuleInspector;

		wil::shared_handle ProcessHandle;
	};
}


