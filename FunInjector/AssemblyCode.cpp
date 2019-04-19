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
	}

	void AssemblyInstruction::ModifyOperands(const std::initializer_list<std::variant<DWORD64, DWORD, WORD>>& InstOperands) noexcept
	{
		auto OperandIndex = 0;
		for (const auto& Operand : InstOperands)
		{
			Operands[OperandIndex] = Operand;
			OperandIndex++;
		}
	}

	int AssemblyInstruction::GetInstructionSize() const noexcept
	{
		int TotalSize = OpCodeBuffer.size();
 
		auto OperandVisitor = [&](auto&& Value)
		{
			TotalSize += sizeof(Value);
		};

		for (auto& Operand : Operands)
		{
			std::visit(OperandVisitor, Operand);
		}
		
		return TotalSize;
	}

	ByteBuffer AssemblyInstruction::GetInstructionBuffer() const noexcept
	{
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
	}

	std::string AssemblyInstruction::FormatIntoString() const noexcept
	{
		std::stringstream StrStream;

		auto OperandVisitor = [&](auto&& Value)
		{
			auto ByteArrString = BufferToString(IntegerToByteBuffer(Value));
			StrStream << ByteArrString << "(" << std::hex << Value << ")";
		};

		StrStream << BufferToString(OpCodeBuffer);
		
		for (auto& Operand : Operands)
		{
			std::visit(OperandVisitor, Operand);
		}

		return StrStream.str();
	}

	AssemblyCode::AssemblyCode(const AssemblyCodeDecl& Instructions)
	{
		Initialize(Instructions);
	}

	void AssemblyCode::Initialize(const AssemblyCodeDecl& Instructions) noexcept
	{
		CodeSize = 0;
		for (const auto& Instruction : Instructions)
		{
			CodeInstructions.emplace_back(Instruction);
			CodeSize += CodeInstructions.back().GetInstructionSize();
		}
		GenerateCodeBuffer();
	}

	void AssemblyCode::ModifyOperandsInOrder(const std::initializer_list< std::initializer_list<Operand>>& Operands) noexcept
	{
		if (Operands.size() != CodeInstructions.size())
		{
			LOG_ERROR << L"Failed to modify operand by order because input amount of instructions does not equal to actual amount";
			return;
		}

		auto IterInstructions = CodeInstructions.begin();
		for (const auto& InstructionOperands : Operands )
		{
			IterInstructions->ModifyOperands(InstructionOperands);
			IterInstructions++;
		}
	}

	void AssemblyCode::GenerateCodeBuffer() noexcept
	{
		for (const auto& Instruction : CodeInstructions)
		{
			const auto& InstrBuffer = Instruction.GetInstructionBuffer();
			CodeBuffer.insert(CodeBuffer.end(), InstrBuffer.cbegin(), InstrBuffer.cend());
		}
	}
}

