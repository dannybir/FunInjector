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
			CodeGenerator = AssemblyCodeGenerator32();
		}
	}

	auto AssemblyCodeManager::GetAssemblyCodeByName(const std::wstring& CodeName)
	{
		auto Iterator = std::find_if(std::begin(AssemblyCodeList), std::end(AssemblyCodeList),
			[&](auto & AssemblyCodePair)
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

		return Iterator;
	}

	auto AssemblyCodeManager::GetAssemblyCodeByName(const std::wstring& CodeName) const
	{
		auto Iterator = std::find_if(std::begin(AssemblyCodeList), std::end(AssemblyCodeList),
			[&](auto & AssemblyCodePair)
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

		return Iterator;
	}

	void AssemblyCodeManager::AddAssemblyCode(const std::wstring& CodeName, ECodeType CodeType)
	{

		RemoteAssemblyCode RAssemblyCode;
		RAssemblyCode.Code = CodeGenerator.GeneratorMap[CodeType]();
		RAssemblyCode.RemoteAddress = 0;

		AssemblyCodeList.push_back( std::make_pair(CodeName, RAssemblyCode));
	}

	std::optional<RemoteAssemblyCode> AssemblyCodeManager::GetAssemblyCodeCopy(const std::wstring& CodeName) const
	{
		auto CodeIterator = GetAssemblyCodeByName(CodeName);
		if (CodeIterator != std::end(AssemblyCodeList))
		{
			return CodeIterator->second;
		}
		else
		{
			return std::nullopt;
		}
	}

	// TODO: Cache this
	void AssemblyCodeManager::SetupCodeAddresses(DWORD64 BaseAddress)
	{
		DWORD64 Offset = 0;
		for (auto& [CodeName, RemoteCode] : AssemblyCodeList)
		{
			RemoteCode.RemoteAddress = BaseAddress + Offset;
			Offset += RemoteCode.Code.GetCodeSize();
		}
	}

	// TODO: Cache this
	SIZE_T AssemblyCodeManager::GetTotalCodeSize() const
	{
		SIZE_T TotalSize = 0;
		for (const auto&[CodeName, RemoteCode] : AssemblyCodeList)
		{
			TotalSize += RemoteCode.Code.GetCodeSize();
		}

		return TotalSize;

	}

	DWORD64 AssemblyCodeManager::GetCodeMemoryLocationFor(const std::wstring & CodeName) const
	{
		auto CodeIterator = GetAssemblyCodeByName(CodeName);
		if (CodeIterator != std::end(AssemblyCodeList))
		{
			return CodeIterator->second.RemoteAddress;
		}

		return 0;
	}

	ByteBuffer AssemblyCodeManager::GetAllCodeBuffer() const
	{
		ByteBuffer FinalBuffer;

		for (const auto& RemoteCode : AssemblyCodeList)
		{
			AppendBufferToBuffer(FinalBuffer, RemoteCode.second.Code.GetCodeBuffer());
		}

		return FinalBuffer;
	}

	void AssemblyCodeManager::ModifyOperandsFor(const std::wstring& CodeName, const std::initializer_list<std::initializer_list<Operand>>& Operands)
	{
		auto ListIterator = GetAssemblyCodeByName(CodeName);
		if (ListIterator != AssemblyCodeList.end())
		{
			ListIterator->second.Code.ModifyOperandsInOrder(Operands);
		}
	}

	Operand AssemblyCodeManager::TranslateOperandSize(Operand OperandVal) const noexcept
	{
		if (ManagerBitnessMode == ECodeBitnessMode::X86)
		{
			if (OperandVal.index() == 0)
			{
				return static_cast<DWORD>(std::get<0>(OperandVal));
			}
		}

		return OperandVal;
	}

}

