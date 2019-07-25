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
		std::filesystem::path GetProcessPath() const;
		bool DetermineIsProcess64Bit() const;

	private:
		wil::shared_handle ProcessHandle;

	public:
		// 
		std::filesystem::path ProcessPath;

		//
		bool IsProcess64Bit = false;

		//

	};
}



