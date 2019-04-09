// FunInjector.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include "FunInjectorAPI.h"

#include "ProcessInformationUtils.h"

namespace FunInjector
{
	// TODO: This is an example of a library function
	void InjectDll()
	{
		static plog::ColorConsoleAppender<plog::TxtFormatter> ColorConsoleLogger;
		plog::init(plog::debug, &ColorConsoleLogger);

		DWORD ProcId = 15600;
		auto ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, ProcId);

		ProcessInformationUtils ProcUtils(ProcessHandle, true);
		auto FreeMemory = ProcUtils.FindFreeMemoryRegion(0x200);
		auto AllocationBase = ProcUtils.AllocateMemoryInProcessForExecution(FreeMemory, 0x100);

		ByteBuffer buffer;
		buffer.push_back('D');
		buffer.push_back('A');
		buffer.push_back('N');
		buffer.push_back('N');
		buffer.push_back('Y');
		buffer.push_back('A');

		ProcUtils.WriteBufferToProcess(buffer, AllocationBase, buffer.size());


		int x = 1;
	}
}

