#include "pch.h"
#include "ProcessMemoryInspector.h"


namespace FunInjector::ProcessInspector
{
	ProcessMemoryInspector::ProcessMemoryInspector(wil::shared_handle ProcHandle)
		: ProcessHandle(ProcHandle)
	{
	}

	ByteBuffer ProcessMemoryInspector::ReadBufferFromProcess(DWORD64 ReadAddress, SIZE_T ReadSize) const noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		// This is the buffer we will read into, pre-allocate with supplied size
		ByteBuffer ReadBuffer(ReadSize);
		SIZE_T ActualReadSize = 0;

		if (ReadProcessMemory(ProcessHandle.get(), reinterpret_cast<PVOID>(ReadAddress), &ReadBuffer[0], ReadSize, &ActualReadSize))
		{
			// Check that we read the amount we wanted
			if (ReadSize == ActualReadSize)
			{
				return ReadBuffer;
			}

			LOG_ERROR << L"Tried to read: " << ReadSize << L" bytes from from memory address: " << std::hex << ReadAddress
				<< L", but was only able to read: " << ActualReadSize << L", will return an empty buffer instead";
			return ByteBuffer();
		}

		LOG_ERROR << L"Failed to read: " << ReadSize << L" bytes from from memory address: " << std::hex << ReadAddress
			<< L", there might be an issue with access qualifiers for the process handle, will return an empty buffer, Error=" << GetLastError();

		HANDLE_EXCEPTION_END;
		return ByteBuffer();
	}

	EOperationStatus ProcessMemoryInspector::WriteBufferToProcess(const ByteBuffer& WriteBuffer, DWORD64 WriteAddress, SIZE_T WriteSize) const noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		// This is the buffer we will read into, pre-allocate with supplied size
		SIZE_T ActualWriteSize = 0;

		if (WriteProcessMemory(ProcessHandle.get(), reinterpret_cast<PVOID>(WriteAddress), &WriteBuffer[0], WriteSize, &ActualWriteSize))
		{
			// Check that we read the amount we wanted
			if (WriteSize == ActualWriteSize)
			{
				LOG_DEBUG << L"Succussefully written: " << ActualWriteSize << L" bytes to address: " << std::hex << WriteAddress;
				return EOperationStatus::SUCCESS;
			}

			LOG_ERROR << L"Tried to write: " << WriteSize << L" bytes to from memory address: " << std::hex << WriteAddress
				<< L", but was only able to write: " << ActualWriteSize << L", consider this operation as failed";
			return EOperationStatus::FAIL;
		}

		LOG_ERROR << L"Failed to write: " << WriteSize << L" bytes from to memory address: " << std::hex << WriteAddress
			<< L", there might be an issue with access qualifiers for the process handle, consider this operation as failed, Error=" << GetLastError();

		HANDLE_EXCEPTION_END;

		return EOperationStatus::FAIL;
	}

	DWORD64 ProcessMemoryInspector::FindFreeMemoryRegion(DWORD64 ScanLocation, SIZE_T FreeMemorySize, bool ScanDown) const noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		PVOID ScanLocationPtr = reinterpret_cast<PVOID>(ScanLocation);

		// Get information about the memory layout at the start of the scan location
		MEMORY_BASIC_INFORMATION MemInfo{ 0 };
		if (VirtualQueryEx(ProcessHandle.get(), ScanLocationPtr, &MemInfo, sizeof(MemInfo)) == 0)
		{
			LOG_ERROR << L"Tried to VirtualQuery memory address: " << std::hex << L", but this failed with Error= " << std::hex << GetLastError();
			return 0;
		}

		// Keep trying to find a region big enough to fit 
		while (MemInfo.State != MEM_FREE || MemInfo.RegionSize < FreeMemorySize)
		{
			// Go up/down in addresses depenending on ScanDown parameter, skip entire unwanted regions
			int DirectionMultiplier = (ScanDown) ? -1 : 1;
			ScanLocationPtr = reinterpret_cast<PVOID>(reinterpret_cast<DWORD64>(ScanLocationPtr) + (DirectionMultiplier * MemInfo.RegionSize));

			if (VirtualQueryEx(ProcessHandle.get(), ScanLocationPtr, &MemInfo, sizeof(MemInfo)) == 0)
			{
				LOG_ERROR << L"Tried to VirtualQuery memory address: " << std::hex << L", but this failed with Error= " << std::hex << GetLastError();
				return 0;
			}

			if (reinterpret_cast<DWORD64>(MemInfo.BaseAddress) == 0)
			{
				// Probably reached memory start here and found nothing
				LOG_WARNING << L"While looking for free memory, got to region with BaseAddress = 0";
				return 0;
			}
		}

		LOG_DEBUG << L"Found a free memory region with size: " << MemInfo.RegionSize << L", in location: " << std::hex << MemInfo.BaseAddress;
		return reinterpret_cast<DWORD64>(ScanLocationPtr);

		HANDLE_EXCEPTION_END;
		return 0;
	}

	DWORD64 ProcessMemoryInspector::AllocateMemoryInProcessForExecution(DWORD64 MemoryAddress, SIZE_T AllocationSize) const noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		PVOID AllocationBase = VirtualAllocEx(ProcessHandle.get(), reinterpret_cast<PVOID>(MemoryAddress), AllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (AllocationBase != nullptr)
		{
			LOG_DEBUG << L"Successefully Allocated: " << AllocationSize << L" bytes in memory address: "
				<< std::hex << MemoryAddress << L" with PAGE_EXECUTE_READWRITE protection";
			return reinterpret_cast<DWORD64>(AllocationBase);
		}

		// If allocating PAGE_EXECUTE_READWRITE fails, try to allocate instead PAGE_READWRITE and then reprotecting the memory
		LOG_WARNING << L"Failed to allocate: " << AllocationSize << L" bytes in memory address: "
			<< std::hex << MemoryAddress << L" with PAGE_EXECUTE_READWRITE protection, Error= " << GetLastError();

		AllocationBase = VirtualAllocEx(ProcessHandle.get(), reinterpret_cast<PVOID>(MemoryAddress), AllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (AllocationBase == nullptr)
		{
			// We fail to allocate even a RW page, guess something is wrong with the process handle
			LOG_WARNING << L"Failed to allocate: " << AllocationSize << L" bytes in memory address: "
				<< std::hex << MemoryAddress << L" with PAGE_READWRITE protection. Process handle may have insufficent access priviliges"
				<< L", Error= " << GetLastError();

			return 0;
		}

		// Try to reprotect the page to be executeable
		DWORD OldProtect = 0;
		if (!VirtualProtectEx(ProcessHandle.get(), AllocationBase, AllocationSize, PAGE_EXECUTE_READWRITE, &OldProtect))
		{
			LOG_ERROR << L"Failed to reprotect memory address: " << std::hex << AllocationBase << L" with PAGE_EXECUTE_READWRITE protection"
				<< L", although allocation was successeful, the allocated is not executeable, so we return 0" << L", Error= " << GetLastError();;
			return 0;
		}

		LOG_DEBUG << L"Successefully Allocated: " << AllocationSize << L" bytes in memory address: "
			<< std::hex << MemoryAddress << L" with PAGE_EXECUTE_READWRITE protection";

		return reinterpret_cast<DWORD64>(AllocationBase);

		HANDLE_EXCEPTION_END;
		return 0;
	}

	DWORD64 ProcessMemoryInspector::FindAndAllocateExecuteMemoryInProcess(DWORD64 BaseSearchAddress, SIZE_T AllocSize) const noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		auto FreeMemoryRegionAddress = BaseSearchAddress;
		DWORD64 AllocationAddress = 0;

		// Scan down in addresses until a suitable memory region is found
		// If AllocSize is too big, its possible we won't find anything
		do
		{
			FreeMemoryRegionAddress = FindFreeMemoryRegion(FreeMemoryRegionAddress, AllocSize);
			AllocationAddress = AllocateMemoryInProcessForExecution(FreeMemoryRegionAddress, AllocSize);

			if (AllocationAddress != 0)
			{
				return AllocationAddress;
			}

			MEMORY_BASIC_INFORMATION MemInfo{ 0 };
			if (VirtualQueryEx(ProcessHandle.get(), reinterpret_cast<PVOID>(FreeMemoryRegionAddress), &MemInfo, sizeof(MemInfo)) == 0)
			{
				LOG_ERROR << L"Tried to VirtualQuery memory address: " << std::hex << FreeMemoryRegionAddress << L", but this failed with Error= " << std::hex << GetLastError();
				return 0;
			}

			FreeMemoryRegionAddress = FreeMemoryRegionAddress - MemInfo.RegionSize;

		} while (FreeMemoryRegionAddress != 0 && AllocationAddress == 0);

		return AllocationAddress;

		HANDLE_EXCEPTION_END;
		return 0;
	}

	using BaseAndSizeOptional = std::optional< std::pair<DWORD64, DWORD> >;
	BaseAndSizeOptional ProcessMemoryInspector::FindClosestImageBaseAndSize(DWORD64 ScanLocation, bool ScanDown) const noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		PVOID ScanLocationPtr = reinterpret_cast<PVOID>(ScanLocation);

		// Get information about the memory layout at the start of the scan location
		MEMORY_BASIC_INFORMATION MemInfo{ 0 };
		if (VirtualQueryEx(ProcessHandle.get(), ScanLocationPtr, &MemInfo, sizeof(MemInfo)) == 0)
		{
			LOG_ERROR << L"Tried to VirtualQuery memory address: " << std::hex << L", but this failed with Error= " << std::hex << GetLastError();
			return std::nullopt;
		}

		// Keep trying to find a region big enough to fit 
		while (MemInfo.Type != MEM_IMAGE)
		{
			// Go up/down in addresses depenending on ScanDown parameter, skip entire unwanted regions
			int DirectionMultiplier = (ScanDown) ? -1 : 1;
			ScanLocationPtr = reinterpret_cast<PVOID>(reinterpret_cast<DWORD64>(ScanLocationPtr) + (DirectionMultiplier * MemInfo.RegionSize));

			if (VirtualQueryEx(ProcessHandle.get(), ScanLocationPtr, &MemInfo, sizeof(MemInfo)) == 0)
			{
				LOG_ERROR << L"Tried to VirtualQuery memory address: " << std::hex << L", but this failed with Error= " << std::hex << GetLastError();
				return std::nullopt;
			}

			if (reinterpret_cast<DWORD64>(MemInfo.BaseAddress) == 0)
			{
				// Probably reached memory start here and found nothing
				LOG_WARNING << L"While looking for an image, got to region with BaseAddress = 0";
				return std::nullopt;
			}
		}

		// If we got here , we found the start of the image
		DWORD64 ImageBase = reinterpret_cast<DWORD64>( ScanLocationPtr );

		// Now we need to calculate the size, to do this, we keep scanning until we reach a memory region
		// that its type is not a MEM_IMAGE
		// An image may be split into subregions, where each subregion represents a section of the PE file
		DWORD ImageSize = 0;
		while (MemInfo.Type == MEM_IMAGE)
		{
			ImageSize += MemInfo.RegionSize;

			// Go up/down in addresses depenending on ScanDown parameter, skip entire unwanted regions
			int DirectionMultiplier = (ScanDown) ? -1 : 1;
			ScanLocationPtr = reinterpret_cast<PVOID>(reinterpret_cast<DWORD64>(ScanLocationPtr) + (DirectionMultiplier * MemInfo.RegionSize));

			if (VirtualQueryEx(ProcessHandle.get(), ScanLocationPtr, &MemInfo, sizeof(MemInfo)) == 0)
			{
				LOG_ERROR << L"Tried to VirtualQuery memory address: " << std::hex << L", but this failed with Error= " << std::hex << GetLastError();
				return std::nullopt;
			}

			if (reinterpret_cast<DWORD64>(MemInfo.BaseAddress) == 0)
			{
				// Probably reached memory start here and found nothing
				LOG_WARNING << L"While looking for an image, got to region with BaseAddress = 0";
				return std::nullopt;
			}
		}

		return std::make_pair( ImageBase, ImageSize );

		HANDLE_EXCEPTION_END_RET(std::nullopt);
	}
}

