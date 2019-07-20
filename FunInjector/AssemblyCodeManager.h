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

		void AddAssemblyCode(const std::wstring& CodeName, ECodeType CodeType);

		std::optional<RemoteAssemblyCode> GetAssemblyCodeCopy(const std::wstring& CodeName) const;

		void SetupCodeAddresses(DWORD64 BaseAddress);

		SIZE_T GetTotalCodeSize() const;

		DWORD64 GetCodeMemoryLocationFor(const std::wstring& CodeName) const;

		ByteBuffer GetAllCodeBuffer() const;

		void ModifyOperandsFor(const std::wstring& CodeName, const std::initializer_list< std::initializer_list<Operand>>& Operands);

		Operand TranslateOperandSize(Operand OperandVal) const noexcept;

	private:
		auto GetAssemblyCodeByName(const std::wstring& CodeName);
		auto GetAssemblyCodeByName(const std::wstring& CodeName) const;

	private:

		std::vector< std::pair<std::wstring, RemoteAssemblyCode> > AssemblyCodeList;

		IAssemblyCodeGenerator CodeGenerator;
		ECodeBitnessMode ManagerBitnessMode;
	};

}


