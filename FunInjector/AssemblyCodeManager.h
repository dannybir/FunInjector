#pragma once

#include "AssemblyCode.h"
#include "AssemblyCodeGenerator64.h"
#include "AssemblyCodeGenerator32.h"
#include "pch.h"


namespace FunInjector
{
	enum class ECodeBitnessMode
	{
		X86,
		X64,
	};

	struct RemoteAssemblyCode
	{
		AssemblyCode Code;
		DWORD64 RemoteAddress = 0;
	};

	class AssemblyCodeManager
	{
	public:
		AssemblyCodeManager() = default;
		AssemblyCodeManager(ECodeBitnessMode BitnessMode);

		// Adds a snippet of code to the overall code, uses the generator to retrieve the AssemblyCode object
		void AddAssemblyCode(const std::wstring& CodeName, ECodeType CodeType) noexcept;

		// Retrieves a copy of a stored assembly code snippet for a given snippet name
		std::optional<RemoteAssemblyCode> GetAssemblyCodeCopy(const std::wstring& CodeName) const noexcept;

		// Calculates the remote address of each assembly code using a base address
		// After this call, each assembly code will have an address corresponding to a real location
		// in some target process
		void SetupCodeAddresses(DWORD64 BaseAddress) noexcept;

		// Returns the total size in bytes of all the assembly code snippets
		SIZE_T GetTotalCodeSize() const noexcept;

		// Returns a memory location of a certain assembly code by its name
		// The memory location will be a real address only if SetupCodeAddresses was called
		DWORD64 GetCodeMemoryLocationFor(const std::wstring& CodeName) const noexcept;

		// Returns a bytebuffer containing the byte representation of all the assembly code instructions
		ByteBuffer GetAllCodeBuffer() const noexcept;

		// Each assembly code snippet is made out of instructions working with operands
		// Using this function we can change the operands of a certain assembly code snippet
		void ModifyOperandsFor(const std::wstring& CodeName, const std::initializer_list< std::initializer_list<Operand>>& Operands) noexcept;

		// Only used for 32bit mode, receives an operand and casts it to a DWORD, fitting a 32bit process
		Operand TranslateOperandSize(Operand OperandVal) const noexcept;

	private:
		auto GetAssemblyCodeByName(const std::wstring& CodeName);
		auto GetAssemblyCodeByName(const std::wstring& CodeName) const;

	private:
		// An list of assembly code objects, each object holding some instructions
		// This list encompasses the entire assembly injection code
		std::vector< std::pair<std::wstring, RemoteAssemblyCode> > AssemblyCodeList;

		// A code generator generates AssemblyCode objects for 32bit or 64bit
		// Depends on the mode this manager is in
		IAssemblyCodeGenerator CodeGenerator;
		ECodeBitnessMode ManagerBitnessMode;
	};

}


