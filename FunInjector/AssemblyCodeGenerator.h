#pragma once

#include "pch.h"
#include "ProcessInformationUtils.h"

namespace FunInjector
{
	// This instruction can be used in x64 and x86
	// For x86, we must cast to DWORD so that the displacement is limited to 4 bytes
	static ByteBuffer GenerateNearRelativeJump(DWORD64 JumpFrom64, DWORD64 JumpTo64, bool isX86 ) noexcept
	{
		// Cast to a 32bit address if we wish the displacement to be 32bit in size
		auto JumpFrom = (isX86) ? static_cast<DWORD>(JumpFrom64) : JumpFrom64;
		auto JumpTo = (isX86) ? static_cast<DWORD>(JumpTo64) : JumpTo64;

		ByteBuffer JumpInstruction;

		// e9 - jmp opcode
		JumpInstruction.push_back(0xe9);

		// e9 requires a signed displacement value as an operand
		// We need to first calculate the displacement in terms of RIP = RIP + 32

		// The instruction is 5 bytes in total, 4 bytes for the displacement and 1 for the opcode
		int InstructionSize = 0x5;
		auto JumpStart = static_cast<long>(JumpFrom + InstructionSize);
		auto JumpDisplacement = static_cast<long>(JumpTo) - JumpStart;

		// Turn the displacement into a byte array and append to the instruction byte array
		// JumpInstruction should now contain 0xe9 0x?? 0x?? 0x?? 0x??
		auto JumpDisplacementBuffer = IntegerToByteBuffer(JumpDisplacement);
		JumpInstruction.insert(std::end(JumpInstruction), std::begin(JumpDisplacementBuffer), std::end(JumpDisplacementBuffer));

		return JumpInstruction;
	}

	// This instruction can be used in 32bit only with 32bit addresses
	static ByteBuffer GenerateNearAbsoluteJump(DWORD64 JumpTo) noexcept
	{
		ByteBuffer JumpInstruction;

		// 0xff 0x25 is the near absolute jump where the operand is a 64 bit address 
		JumpInstruction.push_back(0xff);
		JumpInstruction.push_back(0x25);
		JumpInstruction.push_back(0x00);
		JumpInstruction.push_back(0x00);
		JumpInstruction.push_back(0x00);
		JumpInstruction.push_back(0x00);

		// JumpInstruction should now contain 0xe9 0x?? 0x?? 0x?? 0x??
		auto JumpDisplacementBuffer = IntegerToByteBuffer(JumpTo);
		JumpInstruction.insert(std::end(JumpInstruction), std::begin(JumpDisplacementBuffer), std::end(JumpDisplacementBuffer));

		return JumpInstruction;
	}

	static ByteBuffer GenerateX86Trampoline(ByteBuffer FunctionCode, DWORD64 JumpLocation) noexcept
	{
		// A trampoline consists of a few instructions of the start of the original function before it was hooked
		// In its end is a jump instruction to continuiation of the original function in its original memory location
		// So if OriginalFunctionStart = X, The trampoline will have code from X to X+15, and the jump will jump to X+16
		ByteBuffer TrampolineBuffer;

	}
}