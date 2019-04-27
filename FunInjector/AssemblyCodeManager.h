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

		RemoteAssemblyCode AddOrReturnByName(const std::string& CodeName, ECodeType CodeType);
		void SetupCodeAddresses(DWORD64 BaseAddress);


		void ModifyOperandsFor(const std::string& CodeName, const std::initializer_list< std::initializer_list<Operand>>& Operands);

	private:
		std::optional<RemoteAssemblyCode> GetAssemblyCodeByName(const std::string& CodeName) const;

	private:

		std::vector< std::pair<std::string, RemoteAssemblyCode> > AssemblyCodeList;

		IAssemblyCodeGenerator CodeGenerator;
		ECodeBitnessMode ManagerBitnessMode;
	};

}


