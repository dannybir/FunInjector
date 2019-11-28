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

	void AssemblyCodeManager::AddAssemblyCode(const std::wstring& CodeName, ECodeType CodeType) noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		RemoteAssemblyCode RAssemblyCode;
		RAssemblyCode.Code = CodeGenerator.GeneratorMap[CodeType]();
		RAssemblyCode.RemoteAddress = 0;

		AssemblyCodeList.push_back( std::make_pair(CodeName, RAssemblyCode));

		HANDLE_EXCEPTION_END;
	}

	std::optional<RemoteAssemblyCode> AssemblyCodeManager::GetAssemblyCodeCopy(const std::wstring& CodeName) const noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		auto CodeIterator = GetAssemblyCodeByName(CodeName);
		if (CodeIterator != std::end(AssemblyCodeList))
		{
			return CodeIterator->second;
		}
		else
		{
			return std::nullopt;
		}

		HANDLE_EXCEPTION_END_RET(std::nullopt);
	}

	// TODO: Cache this
	void AssemblyCodeManager::SetupCodeAddresses(DWORD64 BaseAddress) noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		DWORD64 Offset = 0;
		for (auto& [CodeName, RemoteCode] : AssemblyCodeList)
		{
			RemoteCode.RemoteAddress = BaseAddress + Offset;
			Offset += RemoteCode.Code.GetCodeSize();
		}

		HANDLE_EXCEPTION_END;
	}

	// TODO: Cache this
	SIZE_T AssemblyCodeManager::GetTotalCodeSize() const noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		SIZE_T TotalSize = 0;
		for (const auto&[CodeName, RemoteCode] : AssemblyCodeList)
		{
			TotalSize += RemoteCode.Code.GetCodeSize();
		}

		return TotalSize;

		HANDLE_EXCEPTION_END_RET(0);
	}

	DWORD64 AssemblyCodeManager::GetCodeMemoryLocationFor(const std::wstring & CodeName) const noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		auto CodeIterator = GetAssemblyCodeByName(CodeName);
		if (CodeIterator != std::end(AssemblyCodeList))
		{
			return CodeIterator->second.RemoteAddress;
		}

		HANDLE_EXCEPTION_END;
		return 0;
	}

	ByteBuffer AssemblyCodeManager::GetAllCodeBuffer() const noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		ByteBuffer FinalBuffer;

		for (const auto& RemoteCode : AssemblyCodeList)
		{
			AppendBufferToBuffer(FinalBuffer, RemoteCode.second.Code.GetCodeBuffer());
		}

		return FinalBuffer;

		HANDLE_EXCEPTION_END_RET(ByteBuffer());
	}

	void AssemblyCodeManager::ModifyOperandsFor(const std::wstring& CodeName, 
		const std::initializer_list<std::initializer_list<Operand>>& Operands) noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		auto ListIterator = GetAssemblyCodeByName(CodeName);
		if (ListIterator != AssemblyCodeList.end())
		{
			ListIterator->second.Code.ModifyOperandsInOrder(Operands);
		}

		HANDLE_EXCEPTION_END;
	}

	Operand AssemblyCodeManager::TranslateOperandSize(Operand OperandVal) const noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		if (ManagerBitnessMode == ECodeBitnessMode::X86)
		{
			if (OperandVal.index() == 0)
			{
				return static_cast<DWORD>(std::get<0>(OperandVal));
			}
		}

		return OperandVal;

		HANDLE_EXCEPTION_END_RET(Operand());
	}

}

