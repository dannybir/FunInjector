#pragma once

#include "pch.h"

namespace FunInjector
{
	class ProcessInformationUtils
	{
	public:
		ProcessInformationUtils(HANDLE ProcHandle);
		~ProcessInformationUtils() = default;





	private:
		HANDLE ProcessHandle;
	};
}



