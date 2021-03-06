#pragma once

#include "ByteBuffer.h"

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

		auto GetInstructionSize() const noexcept;
		ByteBuffer GetInstructionBuffer() const noexcept;
		std::wstring FormatIntoString() const noexcept;

		inline bool DoesContainsOperands() const { return Operands.size() == 0 ? false : true; }

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

		inline auto  GetCodeSize() const noexcept
		{
			return CodeSize;
		}

		void ModifyOperandsInOrder(const std::initializer_list< std::initializer_list<Operand>>& Operands) noexcept;

		inline ByteBuffer GetCodeBuffer() const noexcept
		{
			return CodeBuffer;
		}

		std::wstring FormatIntoString() const;


		// TODO: Should probably go into some utils file
		static long CalculateRelativeJumpDisplacement(DWORD64 JumpFrom, DWORD64 JumpTo)
		{
			// A relative jump is of the form RIP = RIP + 32Bit Displacement
			// The displacement is a signed integer, which is sign extented to 64bit in 64bit mode
			// So its calculation is the following:
			// Displacement = TargetAddress - RIP, where RIP = JumpFrom + Jump instruction size
			int InstructionSize = 1 + sizeof(long);
			auto JumpStart = static_cast<long>(JumpFrom + InstructionSize);
			return static_cast<long>(JumpTo) - JumpStart;
		}

		
		static AssemblyCode PrepareRelativeJump(DWORD64 JumpFrom, DWORD64 JumpTo)
		{
			return { {0xe9_b, static_cast<DWORD>(CalculateRelativeJumpDisplacement(JumpFrom, JumpTo)) } };
		}

	private:
		void GenerateCodeBuffer() noexcept;

	private:
		std::vector< AssemblyInstruction > CodeInstructions;

		ByteBuffer CodeBuffer;

		size_t CodeSize;
	};
}


