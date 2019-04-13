#pragma once

#include "pch.h"
#include "ProcessInformationUtils.h"

namespace FunInjector
{
	// This instruction can be used in x64 and x86
	// Be aware that this allows 2GB maximum relative displacement due to limitation of a signed 4 byte displacement
	// The long type displacement is sign extended ( keeps sign after extending ) to 64bit in 64bit mode
	static ByteBuffer GenerateRelativeJumpCode( DWORD64 JumpFrom, DWORD64 JumpTo ) noexcept
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
		AppendIntegerToBuffer(JumpInstruction, static_cast<unsigned int>(0) );

		// 
		AppendIntegerToBuffer(JumpInstruction, JumpTo);

		return JumpInstruction;
	}

	static ByteBuffer GenerateUnhookCode(const ProcessInformationUtils& ProcUtils,
		DWORD64 FunctionAddress, DWORD64 FunctionBackupBufferAddress, DWORD FunctionBackupSize )
	{
		// Helper functions here
		auto WriteProcessMemoryPtr = ProcUtils.GetFunctionAddress("ntdll!memcpy");
		auto FlushInstructionCachePtr = ProcUtils.GetFunctionAddress("kernelbase!FlushInstructionCache");

		ByteBuffer UnhookCode;

		// mov rcx, FunctionAddress ( rcx = lpBaseAddress ) | 48 ba FunctionAddress
		UnhookCode.push_back(0x48); UnhookCode.push_back(0xb9); AppendIntegerToBuffer(UnhookCode, FunctionAddress);

		// mov rdx, FunctionBackupBufferAddress ( rdx = lpBuffer ) | 49 b8 FunctionBackupBufferAddress
		UnhookCode.push_back(0x48); UnhookCode.push_back(0xba); AppendIntegerToBuffer(UnhookCode, FunctionBackupBufferAddress);

		// mov r8, FunctionBackupSize ( r8 = nSize ) | c7 c1 FunctionBackupSize
		UnhookCode.push_back(0x49); UnhookCode.push_back(0xc7); UnhookCode.push_back(0xc0); AppendIntegerToBuffer(UnhookCode, FunctionBackupSize);

		// mov rdi, WriteProcessMemoryPtr | 48 bf WriteProcessMemoryPtr
		UnhookCode.push_back(0x48); UnhookCode.push_back(0xbf); AppendIntegerToBuffer(UnhookCode, WriteProcessMemoryPtr);

		// call rdi || ff d7
		UnhookCode.push_back(0xff); UnhookCode.push_back(0xd7);


		// mov rdi, FlushInstructionCachePtr
		//UnhookCode.push_back(0x48); UnhookCode.push_back(0xbf); AppendIntegerToBuffer(UnhookCode, FlushInstructionCachePtr);

		//// call rdi
		//UnhookCode.push_back(0xff); UnhookCode.push_back(0xd7);

		auto JmpBuffer = GenerateAbsoluteJump64Code(FunctionAddress);
		UnhookCode.insert(UnhookCode.end(), std::begin(JmpBuffer), std::end(JmpBuffer));
		
		return UnhookCode;

	}
}