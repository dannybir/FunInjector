#pragma once

#include "ProcessInformationInspector.h"

namespace FunInjector::ProcessInspector
{
	class ProcessMemoryInspector
	{
	public:
		ProcessMemoryInspector() = default;
		ProcessMemoryInspector(wil::shared_handle ProcHandle);

		// Read some bytes from the remote process into a buffer
		// Process handle must be opened with correct access rights or this will fail
		ByteBuffer ReadBufferFromProcess(DWORD64 ReadAddress, SIZE_T ReadSize) const noexcept;

		// Write a supplied buffer to a remote process at the given location
		// Process handle must be opened with correct access rights or this will fail
		EOperationStatus WriteBufferToProcess(const ByteBuffer& WriteBuffer, DWORD64 WriteAddress, SIZE_T WriteSize) const noexcept;

		// Find a free memory block that can hold FreeSize amount of room
		// Only looks for free pages, starts looking from ntdll.dll location going down in addresses
		// Will return the address of the start of the free page block
		DWORD64	FindFreeMemoryRegion(DWORD64 ScanLocation, SIZE_T FreeMemorySize, bool ScanDown = true) const noexcept;

		// Allocates a block of memory to be ready for execution, returns the allocation base
		DWORD64 AllocateMemoryInProcessForExecution(DWORD64 MemoryAddress, SIZE_T AllocationSize) const noexcept;

		// Utilizies the two previous functions to scan the memory and locate a free memory region which could be allocated
		// Returns the address to the beginning of aformentioned memory region
		DWORD64 FindAndAllocateExecuteMemoryInProcess(DWORD64 BaseSearchAddress, SIZE_T AllocSize) const noexcept;

	private:
		// A *valid* handle for the process, must contain needed access rights
		wil::shared_handle ProcessHandle = nullptr;
	};
};

