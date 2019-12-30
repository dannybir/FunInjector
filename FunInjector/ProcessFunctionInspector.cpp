#include "pch.h"
#include "ProcessFunctionInspector.h"

namespace FunInjector::ProcessInspector
{
	ProcessFunctionInspector::ProcessFunctionInspector(wil::shared_handle ProcHandle)
		: ProcessHandle( ProcHandle )
	{
	}

	DWORD64 ProcessFunctionInspector::GetRemoteFunctionAddress(const std::string_view FunctionName, const std::string_view ModuleName)
	{
		auto ModuleAddress = ProcModuleInspector->GetModuleAddress(ModuleName.data());
		auto ModuleBuffer = ProcModuleInspector->GetModuleBufferByName(ModuleName.data());

		if (ModuleBuffer.size() == 0)
		{
			LOG_ERROR << "Failed to retrieve a buffer of module: " << ModuleName.data() << L", process may have terminated or module unloaded, returning 0";
			return 0;
		}

		return GetFunctionAddress(FunctionName, ModuleAddress, ModuleBuffer);
	}

	DWORD64 ProcessFunctionInspector::GetFunctionAddress(const std::string_view FunctionName, DWORD64 ModuleBaseAddress, ByteBuffer ModuleBuffer) const
	{
		auto ModBaseInBuffer = reinterpret_cast<unsigned char *>(&ModuleBuffer[0]);

		auto DosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(ModBaseInBuffer);

		// Signature of the DOS header is fixed, this will probably always be ok
		if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return 0;

		auto HeadersPtr = reinterpret_cast<IMAGE_NT_HEADERS *>(ModBaseInBuffer + DosHeader->e_lfanew);
		const bool Is64bit = (HeadersPtr->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) ? true : false;

		// Signature of the NT header is also fixed
		if (HeadersPtr->Signature != IMAGE_NT_SIGNATURE)
			return 0;

		// 64 bit modules have a different rva
		DWORD RvaToExportDir = 0;
		if (Is64bit)
		{
			auto NtHeader = reinterpret_cast<IMAGE_NT_HEADERS64 *>(ModBaseInBuffer + DosHeader->e_lfanew);
			RvaToExportDir = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		}
		else
		{
			auto NtHeader = reinterpret_cast<IMAGE_NT_HEADERS32 *>(ModBaseInBuffer + DosHeader->e_lfanew);
			RvaToExportDir = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		}

		auto ExportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY *>(ModBaseInBuffer + RvaToExportDir);
		
		// A pointer to a list of DWORD sized variables that describe the address of the function relative to the module base
		const auto FunctionListPtr = reinterpret_cast<DWORD*>(ModBaseInBuffer + ExportDirectory->AddressOfFunctions);

		// A pointer to a list of RVA's, i.e offsets from the module base to a function name
		const auto NameListPtr = reinterpret_cast<DWORD*>(ModBaseInBuffer + ExportDirectory->AddressOfNames);

		// A pointer to a list of indicies into the function name list
		const auto NameOrdinalListPtr = reinterpret_cast<WORD*>(ModBaseInBuffer + ExportDirectory->AddressOfNameOrdinals);

		const auto BaseOrdinal = ExportDirectory->Base;
		const auto NumFunctions = ExportDirectory->NumberOfFunctions;
		const auto NumNames = ExportDirectory->NumberOfNames;

		// Go over all the names until we find the name we are looking for
		for (DWORD Index = 0; Index < NumNames; Index++)
		{
			const auto FunctionNamePtr = reinterpret_cast<char*>(ModBaseInBuffer + NameListPtr[Index]);

			if (FunctionNamePtr == nullptr)
				continue;

			std::string CurrentFuncName(FunctionNamePtr);
			if (CurrentFuncName.compare(FunctionName) == 0)
			{
				// We found the function, lets get its address
				// To do that, we must retrive the ordinal number of the function
				// We can do that by indexing the name ordinal list
				WORD CurrentOrdinal = static_cast<WORD>((NameOrdinalListPtr[static_cast<WORD>(Index)]));
				
				// Finally the function address in the remote process will be the RVA 
				// we get from the function list using the ordinal as the index
				// that plus the module base
				return ModuleBaseAddress + static_cast<DWORD64>(FunctionListPtr[CurrentOrdinal]);
			}
		}
		
		LOG_WARNING << L"Was not able to find address of function: " << FunctionName << L", in the export table";
		return 0;
	}
}