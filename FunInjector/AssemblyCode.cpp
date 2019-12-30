#include "pch.h"
#include "AssemblyCode.h"

namespace FunInjector
{
	AssemblyInstruction::AssemblyInstruction(const std::initializer_list<InstructionPart>& Instruction)
	{
		ParseInstruction(Instruction);
	}

	void AssemblyInstruction::ParseInstruction(const std::initializer_list<InstructionPart>& Instruction) noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		auto InstructionPartVisitor = [&]( auto&& Value ) 
		{
			using Type = std::decay_t< decltype(Value)>;

			if constexpr (std::is_same_v< Type, Byte>)
			{
				OpCodeBuffer.push_back(Value);
			}
			else if constexpr (std::is_same_v< Type, DWORD64> ||
				std::is_same_v< Type, DWORD> ||
				std::is_same_v< Type, WORD>)
			{
				Operands.emplace_back(Value);
			}
		};

		for (const auto& InstrPart : Instruction)
		{
			std::visit(InstructionPartVisitor, InstrPart);
		}

		HANDLE_EXCEPTION_END;
	}

	void AssemblyInstruction::ModifyOperands(const std::initializer_list<std::variant<DWORD64, DWORD, WORD>>& InstOperands) noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		if (Operands.size() == 0)
		{
			return;
		}

		auto OperandIndex = 0;
		for (const auto& Operand : InstOperands)
		{
			Operands[OperandIndex] = Operand;
			OperandIndex++;
		}

		HANDLE_EXCEPTION_END;
	}

	auto AssemblyInstruction::GetInstructionSize() const noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		auto TotalSize = OpCodeBuffer.size();
 
		auto OperandVisitor = [&](auto&& Value)
		{
			TotalSize += sizeof(Value);
		};

		for (auto& Operand : Operands)
		{
			std::visit(OperandVisitor, Operand);
		}
		
		return TotalSize;

		HANDLE_EXCEPTION_END_RET(size_t());
	}

	ByteBuffer AssemblyInstruction::GetInstructionBuffer() const noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		ByteBuffer FinalBuffer;

		auto OperandVisitor = [&](auto&& Value)
		{
			AppendIntegerToBuffer(FinalBuffer, Value);
		};

		FinalBuffer.insert(FinalBuffer.end(), OpCodeBuffer.begin(), OpCodeBuffer.end());

		for (auto& Operand : Operands)
		{
			std::visit(OperandVisitor, Operand);
		}

		return FinalBuffer;

		HANDLE_EXCEPTION_END_RET(ByteBuffer());
	}

	std::wstring AssemblyInstruction::FormatIntoString() const noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		std::wstringstream StrStream;

		auto OperandVisitor = [&](auto&& Value)
		{
			auto ByteArrString = BufferToString<wchar_t>(IntegerToByteBuffer(Value));
			StrStream << ByteArrString << "(" << std::hex << Value << ")";
		};

		StrStream << "[" << BufferToString<wchar_t>(OpCodeBuffer) << "]";
		StrStream << "[";
		for (auto& Operand : Operands)
		{
			std::visit(OperandVisitor, Operand);
			StrStream << ", ";
		}
		StrStream << "]";

		return StrStream.str();

		HANDLE_EXCEPTION_END_RET(std::wstring());
	}

	AssemblyCode::AssemblyCode(const AssemblyCodeDecl& Instructions)
	{
		Initialize(Instructions);
	}

	void AssemblyCode::Initialize(const AssemblyCodeDecl& Instructions) noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		CodeSize = 0;
		for (const auto& Instruction : Instructions)
		{
			CodeInstructions.emplace_back(Instruction);
			CodeSize += CodeInstructions.back().GetInstructionSize();
		}
		GenerateCodeBuffer();

		HANDLE_EXCEPTION_END;
	}

	void AssemblyCode::ModifyOperandsInOrder(const std::initializer_list< std::initializer_list<Operand>>& Operands) noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		auto IterInstructions = CodeInstructions.begin();
		for (const auto& InstructionOperands : Operands )
		{
			while (!IterInstructions->DoesContainsOperands())
			{
				IterInstructions++;
			}

			if (IterInstructions == CodeInstructions.end())
			{
				break;
			}

			IterInstructions->ModifyOperands(InstructionOperands);
			IterInstructions++;
		}

		GenerateCodeBuffer();

		HANDLE_EXCEPTION_END;
	}

	std::wstring AssemblyCode::FormatIntoString() const
	{
		std::wostringstream StringStream;

		StringStream << std::endl;
		int InstructionNumber = 0;
		for (const auto& Instruction : CodeInstructions)
		{
			StringStream << InstructionNumber << ": " << Instruction.FormatIntoString() << std::endl;
			InstructionNumber++;
		}

		return StringStream.str();
	}

	void AssemblyCode::GenerateCodeBuffer() noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		CodeBuffer.clear();

		for (const auto& Instruction : CodeInstructions)
		{
			const auto& InstrBuffer = Instruction.GetInstructionBuffer();
			CodeBuffer.insert(CodeBuffer.end(), InstrBuffer.cbegin(), InstrBuffer.cend());
		}

		HANDLE_EXCEPTION_END;
	}
}

