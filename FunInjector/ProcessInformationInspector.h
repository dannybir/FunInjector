#pragma once

#include "pch.h"

namespace FunInjector::ProcessInspector
{
	class ProcessInformationInspector
	{
	public:
		ProcessInformationInspector(wil::shared_handle ProcHandle);
		EOperationStatus RetrieveInformation() noexcept;

	private:
		bool DetermineIsProcess64Bit() const;

	private:
		wil::shared_handle ProcessHandle;

	public:
		bool IsProcess64Bit = false;
	};
}



