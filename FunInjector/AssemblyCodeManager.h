#pragma once

#include "AssemblyCode.h"
#include "AssemblyCodeGenerator64.h"
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
		DWORD64 RemoteAddress;
	};

	class AssemblyCodeManager
	{
	public:
		AssemblyCodeManager() = default;
		AssemblyCodeManager(ECodeBitnessMode BitnessMode);

		void AddAssemblyCode(const std::string& CodeName, ECodeType CodeType);

		std::optional<RemoteAssemblyCode> GetAssemblyCodeCopy(const std::string& CodeName) const;

		void SetupCodeAddresses(DWORD64 BaseAddress);

		SIZE_T GetTotalCodeSize() const;

		DWORD64 GetCodeMemoryLocationFor(const std::string& CodeName) const;

		ByteBuffer GetAllCodeBuffer() const;

		void ModifyOperandsFor(const std::string& CodeName, const std::initializer_list< std::initializer_list<Operand>>& Operands);

	private:
		auto GetAssemblyCodeByName(const std::string& CodeName);
		auto GetAssemblyCodeByName(const std::string& CodeName) const;

	private:

		std::vector< std::pair<std::string, RemoteAssemblyCode> > AssemblyCodeList;

		IAssemblyCodeGenerator CodeGenerator;
		ECodeBitnessMode ManagerBitnessMode;
	};

}


