// FunInjector.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include "FunInjectorAPI.h"

#include "AssemblyCodeGenerator.h"
#include "ProcessInformationUtils.h"

namespace FunInjector
{
	// TODO: This is an example of a library function
	void InjectDll()
	{
		static plog::ColorConsoleAppender<plog::TxtFormatter> ColorConsoleLogger;
		plog::init(plog::debug, &ColorConsoleLogger);

		DWORD ProcId = 20084;
		auto ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, ProcId);

		ProcessInformationUtils ProcUtils(ProcessHandle, true);
		auto AllocationBase = ProcUtils.FindAndAllocateExecuteMemoryInProcess(0x200);

		auto FunctionAddr = ProcUtils.GetFunctionAddress(L"kernelbase!ReplaceFileW");

		auto JumpInstrBuffer =  GenerateNearAbsoluteJump(AllocationBase);
		ProcUtils.WriteBufferToProcess(JumpInstrBuffer, FunctionAddr, JumpInstrBuffer.size());

		int x = 1;
	}
}

