#include "pch.h"
#include "AssemblyCodeManager.h"

namespace FunInjector
{
	AssemblyCodeManager::AssemblyCodeManager(ECodeBitnessMode BitnessMode) : ManagerBitnessMode(BitnessMode)
	{
		if (BitnessMode == ECodeBitnessMode::X64)
		{
			CodeGenerator = AssemblyCodeGenerator64();
		}
		else
		{
			//CodeGenerator = AssemblyCodeGenerator32();
		}
	}

	RemoteAssemblyCode AssemblyCodeManager::AddOrReturnByName(const std::string& CodeName, ECodeType CodeType)
	{
		std::optional<RemoteAssemblyCode> CodeOptional = GetAssemblyCodeByName(CodeName);
		if (CodeOptional)
		{
			return CodeOptional.value();
		}

		RemoteAssemblyCode RAssemblyCode;
		RAssemblyCode.Code = CodeGenerator.GeneratorMap[CodeType]();
		RAssemblyCode.RemoteAddress = 0;

		AssemblyCodeList.push_back( std::make_pair(CodeName, RAssemblyCode));

		return RAssemblyCode;
	}

	void AssemblyCodeManager::SetupCodeAddresses(DWORD64 BaseAddress)
	{
		DWORD64 Offset = 0;
		for (auto& [CodeName, RemoteCode] : AssemblyCodeList)
		{
			RemoteCode.RemoteAddress = BaseAddress + Offset;
			Offset += RemoteCode.Code.GetCodeSize();
		}
	}

	void AssemblyCodeManager::ModifyOperandsFor(const std::string& CodeName, const std::initializer_list<std::initializer_list<Operand>>& Operands)
	{
		std::optional<RemoteAssemblyCode> CodeOptional = GetAssemblyCodeByName(CodeName);
		if (CodeOptional)
		{
			CodeOptional->Code.ModifyOperandsInOrder(Operands);
		}
	}

	std::optional<RemoteAssemblyCode> AssemblyCodeManager::GetAssemblyCodeByName(const std::string& CodeName) const
	{

		auto Iterator = std::find_if(AssemblyCodeList.cbegin(), AssemblyCodeList.cend(),
			[&](const auto & AssemblyCodePair)
			{
				if (AssemblyCodePair.first == CodeName)
				{
					return true;
				}
				else
				{
					return false;
				}
			}
		);

		if (Iterator != AssemblyCodeList.end())
		{
			return Iterator->second;
		}
		else
		{
			return std::nullopt;
		}
	}
}

