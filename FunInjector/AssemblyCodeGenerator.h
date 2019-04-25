#pragma once

#include "pch.h"
#include "ProcessInformationUtils.h"
#include "AssemblyCode.h"

namespace FunInjector
{
	namespace JumpInstructions
	{
		enum class JumpInstructionSizes : SIZE_T
		{
			RELATIVE_JUMP = 5,
			ABSOLUTE_JUMP_64 = 14,
		};

		// This instruction can be used in x64 and x86
		// Be aware that this allows 2GB maximum relative displacement due to limitation of a signed 4 byte displacement
		// The long type displacement is sign extended ( keeps sign after extending ) to 64bit in 64bit mode
		static ByteBuffer GenerateRelativeJumpCode(DWORD64 JumpFrom, DWORD64 JumpTo) noexcept
		{
			ByteBuffer JumpInstruction;

			// e9 - jmp opcode
			JumpInstruction.push_back(0xe9);

			// e9 requires a signed displacement value as an operand
			// We need to first calculate the displacement in terms of RIP = RIP + 32

			// The instruction is 5 bytes in total, 4 bytes for the displacement and 1 for the opcode
			int InstructionSize = 1 + sizeof(long);
			auto JumpStart = static_cast<long>(JumpFrom + InstructionSize);
			auto JumpDisplacement = static_cast<long>(JumpTo) - JumpStart;

			// Turn the displacement into a byte array and append to the instruction byte array
			AppendIntegerToBuffer(JumpInstruction, JumpDisplacement);

			return JumpInstruction;
		}

		// This instruction can be used in 32bit but in this case we'll only use it in 64bit
		static ByteBuffer GenerateAbsoluteJump64Code(DWORD64 JumpTo) noexcept
		{
			ByteBuffer JumpInstruction;

			// 0xff 0x25 is a near absolute jump, 0x25 is a mod-r\m byte signifing that the operand of this instruction
			// is a 32bit displacement. in 64 bit mode, this displacement is actually RIP + 32bit Displacement
			// So 0xff 0x25 Displacement translets to: jmp qword ptr [rip + displacement]
			// So we will jump to the address stored at memory location "rip+displacement"
			JumpInstruction.push_back(0xff);
			JumpInstruction.push_back(0x25);

			// Our displacement is 0. This means that our instruction will be jmp qword ptr [rip]
			// rip always hold the memory address of the next instruction
			// So if our next instruction is not an instruction, but our "JumpTo" value instead
			// We will get our needed absolute jump
			AppendIntegerToBuffer(JumpInstruction, static_cast<unsigned int>(0));

			// 
			AppendIntegerToBuffer(JumpInstruction, JumpTo);

			return JumpInstruction;
		}
	}
	

	static AssemblyCode GenerateMemCpyCode64()
	{
		AssemblyCode MemCpyCode(
			{
				// mov rcx, Operand: Target Address
				{ 0x48_b,0xb9_b, DWORD64_OPERAND},

				// mov rdx, Operand: Source Address
				{ 0x48_b,0xba_b, DWORD64_OPERAND},

				// mov r8, Operand: Size to copy
				{ 0x49_b,0xc7_b,0xc0_b, DWORD_OPERAND},

				// mov rdi, Operand: Pointer to function
				{ 0x48_b,0xbf_b,DWORD64_OPERAND},

				// call rdi
				{ 0xff_b, 0xd7_b }
			});
		
		return MemCpyCode;
	}

	static AssemblyCode GenerateVirtualProtectCode64()
	{
		AssemblyCode VirtualProtectCode(
			{
				// add rsp,4
				{ 0x48_b, 0x83_b, 0xc4_b, 0x04_b },

				// mov rcx, Operand = Target Protect Address
				{ 0x48_b, 0xb9_b, DWORD64_OPERAND},

				// mov rdx, Operand = Size of Memory to protect
				{ 0x48_b, 0xc7_b, 0xc2_b, DWORD_OPERAND},

				// mov r8, Operand = New Protect Value
				{ 0x49_b, 0xc7_b, 0xc0_b, DWORD_OPERAND},

				// mov r9, rsp
				{ 0x49_b, 0x89_b, 0xe1_b},

				// mov rdi, Operand = Pointer to VirtualProtect
				{ 0x48_b, 0xbf_b, DWORD64_OPERAND},

				// call rdi
				{ 0xff_b, 0xd7_b},

				// sub rsp,4
				{ 0x48_b, 0x83_b, 0xec_b, 0x04_b}
			}
		);

		return VirtualProtectCode;
	}
}