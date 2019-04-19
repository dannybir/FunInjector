#pragma once

#include "ByteBuffer.h"
#include <tuple>
#include <array>
#include <variant>

/*
	AssemblyCode represents a list of instructions which perform some operation
	AssemblyInstruction can contain a parameter operand if they need to or sometimes not
	CodeParameters contain the parameters in the order they appear in the code
*/
namespace FunInjector
{
	namespace Literals
	{
		constexpr inline Byte operator ""_b(unsigned long long Param)
		{
			return static_cast<Byte>(Param);
		}

		constexpr inline WORD operator ""_w(unsigned long long Param)
		{
			return static_cast<WORD>(Param);
		}

		constexpr inline DWORD operator ""_dw(unsigned long long Param)
		{
			return static_cast<DWORD>(Param);
		}

		constexpr inline DWORD64 operator ""_dw64(unsigned long long Param)
		{
			return static_cast<DWORD64>(Param);
		}
	}

	using InstructionPart = std::variant< DWORD64, DWORD, WORD, Byte >;
	using AssemblyCodeDecl = std::initializer_list< std::initializer_list< InstructionPart > >;
	using Operand = std::variant< DWORD64, DWORD, WORD >;

	using namespace Literals;
	constexpr auto DWORD_OPERAND = 0x00_dw;
	constexpr auto DWORD64_OPERAND = 0x00_dw64;
	constexpr auto WORD_OPERAND = 0x00_w;

	class AssemblyInstruction
	{
	public:
		AssemblyInstruction() = default;
		AssemblyInstruction(const std::initializer_list< InstructionPart >& Instruction);

		void ParseInstruction(const std::initializer_list< InstructionPart >& Instruction) noexcept;

		void ModifyOperands(const std::initializer_list< Operand >& InstOperands) noexcept;

		int GetInstructionSize() const noexcept;
		ByteBuffer GetInstructionBuffer() const noexcept;

		std::string FormatIntoString() const noexcept;

	private:
		// Op codes are made of a byte or a list of bytes that encode some operation
		ByteBuffer OpCodeBuffer;

		// 
		std::vector< Operand > Operands;
	};

	class AssemblyCode
	{
	public:
		AssemblyCode() = default;
		AssemblyCode(const AssemblyCodeDecl& Instructions);

		void Initialize(const AssemblyCodeDecl& Instructions) noexcept;

		inline int  GetCodeSize() const noexcept
		{
			return CodeSize;
		}

		void ModifyOperandsInOrder(const std::initializer_list< std::initializer_list<Operand>>& Operands) noexcept;

		inline ByteBuffer GetCodeBuffer() const noexcept
		{
			return CodeBuffer;
		}

		inline std::string FormatIntoString()
		{
			for (auto instr : CodeInstructions)
			{

			}
		}

	private:
		void GenerateCodeBuffer() noexcept;

	private:
		std::vector< AssemblyInstruction > CodeInstructions;

		ByteBuffer CodeBuffer;

		int CodeSize;
	};
}


