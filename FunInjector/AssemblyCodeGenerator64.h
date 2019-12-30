#pragma once

#include "pch.h"
#include "IAssemblyCodeGenerator.h"

namespace FunInjector
{
	class AssemblyCodeGenerator64 : public IAssemblyCodeGenerator
	{

		static AssemblyCode GenerateLoadDllCode()
		{
			return
			{
				// push rbp
				{ 0x55_b },

				// mov rbp, rsp
				{ 0x48_b, 0x89_b, 0xe5_b },

				// Note on this: Research shows that stack free space
				// must be big enough to hold future variables
				// i.e we need to move the stack pointer down enough to
				// allow for room
				// Research shows that 0x40 is enough, a number lower
				// may cause a crash.
				// sub rsp, 40h
				{ 0x48_b, 0x83_b, 0xec_b, 0x40_b},

				// rbp - 10 = local variable will hold the UNICODE_STRING structure
				// lea rcx, [ rbp - 10 ]
				{ 0x48_b, 0x8d_b, 0x4d_b, 0xf0_b },

				// mov rdx, Operand: Address to path to DLL
				{ 0x48_b, 0xba_b, DWORD64_OPERAND},

				// mov rdi, Operand: Pointer to RtlInitUnicodeString  function
				{ 0x48_b,0xbf_b, DWORD64_OPERAND},

				// call rdi
				{ 0xff_b, 0xd7_b },

				// rbp - 10 now has a unicode string structure that can be used for LdrLoadDll

				// mov r9, Operand = Out module handle
				{ 0x49_b, 0xb9_b, DWORD64_OPERAND},

				// lea r8, [ rbp - 10 ] Module filepath - unicode string set up earlier
				{ 0x4c_b, 0x8d_b, 0x45_b, 0xf0_b },

				// mov rdx, Operand = PathToFile 
				{ 0x48_b, 0xba_b, DWORD64_OPERAND},

				// mov rcx, Operand = flags
				{ 0x48_b, 0xc7_b, 0xc1_b, DWORD_OPERAND},

				// mov rdi, Operand: Pointer to LdrLoadDll  function
				{ 0x48_b,0xbf_b, DWORD64_OPERAND},

				// call rdi
				{ 0xff_b, 0xd7_b },

				// add rsp, 40h
				{ 0x48_b, 0x83_b, 0xc4_b, 0x40_b },

				// mov rsp,rbp
				{ 0x48_b, 0x89_b, 0xec_b },

				// pop rbp
				{ 0x5d_b }
			};
		}

		static AssemblyCode GenerateMemCpyCode()
		{
			return
			{
				// mov r8, Operand: Size to copy
				{ 0x49_b,0xc7_b,0xc0_b, DWORD_OPERAND},

				// mov rdx, Operand: Source Address
				{ 0x48_b,0xba_b, DWORD64_OPERAND},

				// mov rcx, Operand: Target Address
				{ 0x48_b,0xb9_b, DWORD64_OPERAND},

				// mov rdi, Operand: Pointer to function
				{ 0x48_b,0xbf_b,DWORD64_OPERAND},

				// call rdi
				{ 0xff_b, 0xd7_b }
			};
		}

		static AssemblyCode GenerateVirtualProtectCode()
		{
			return
			{
				// TODO: This fails with access denied last error on x64
				// No crash, the function just fails
				// Need to check if parameters are correctly passed
				// sub rsp,54
				{ 0x48_b, 0x83_b, 0xec_b, 0x36_b},

				// mov r9, Operand Old protect pointer
				{ 0x49_b, 0xb9_b, DWORD64_OPERAND},

				// push r9
				{ 0x41_b, 0x51_b },

				// mov r9, Operand = New Protect Value
				{ 0x49_b, 0xc7_b, 0xc1_b, DWORD_OPERAND},

				// mov r8, Operand = Size of Memory to protect
				{ 0x49_b, 0xb8_b, DWORD64_OPERAND},

				// mov rdx, Operand = Target Protect Address
				{ 0x48_b, 0xba_b, DWORD64_OPERAND},

				// GetCurrentProcess , i.e (HANDLE-1) placed into rcx
				{ 0x48_b, 0x83_b, 0xc9_b, 0xff_b },

				// mov rdi, Operand = Pointer to NtProtectVirtualMemory
				{ 0x48_b, 0xbf_b, DWORD64_OPERAND},

				// call rdi
				{ 0xff_b, 0xd7_b},

				// add rsp,54
				{ 0x48_b, 0x83_b, 0xc4_b, 0x36_b },
			};
		}

		static AssemblyCode GenerateFlushInstructionsCode()
		{
			return 
			{
				// GetCurrentProcess , i.e (HANDLE-1) placed into rcx
				{ 0x48_b, 0x83_b, 0xc9_b, 0xff_b },

				// mov r8, Operand: Size to copy
				{ 0x49_b, 0xc7_b, 0xc0_b, DWORD_OPERAND},

				// mov rdx, Operand: Base address
				{ 0x48_b, 0xba_b, DWORD64_OPERAND},

				// mov rdi, Operand: Pointer to function
				{ 0x48_b, 0xbf_b, DWORD64_OPERAND},

				// sub rsp,54
				{ 0x48_b, 0x83_b, 0xec_b, 0x36_b},

				// call rdi
				{ 0xff_b, 0xd7_b },

				// add rsp,54
				{ 0x48_b, 0x83_b, 0xc4_b, 0x36_b },
			};
		}

		static AssemblyCode GeneratePushAllRegisters()
		{
			return
			{
				{0x50_b},
				{0x51_b},
				{0x52_b},
				{0x53_b},
				{0x56_b},
				{0x57_b},
				{0x41_b, 0x50_b},
				{0x41_b, 0x51_b},
				{0x41_b, 0x52_b},
				{0x41_b, 0x53_b},
				{0x41_b, 0x54_b},
				{0x41_b, 0x55_b},
				{0x41_b, 0x56_b},
				{0x41_b, 0x57_b},
			};
		}

		static AssemblyCode GeneratePopAllRegisters()
		{
			return
			{
				{0x41_b, 0x5f_b},
				{0x41_b, 0x5e_b},
				{0x41_b, 0x5d_b},
				{0x41_b, 0x5c_b},
				{0x41_b, 0x5b_b},
				{0x41_b, 0x5a_b},
				{0x41_b, 0x59_b},
				{0x41_b, 0x58_b},
				{0x5f_b},
				{0x5e_b},
				{0x5b_b},
				{0x5a_b},
				{0x59_b},
				{0x58_b}
			};
		}

		static AssemblyCode GenerateRelativeJump()
		{
			return
			{
				// jmp Operand = signed Displacement, where RIP + Displacement = Target
				{ 0xe9_b, DWORD_OPERAND},
			};
		}

		static AssemblyCode GenerateAbsoluteJump()
		{
			return
			{
				// 0xff 0x25 is a near absolute jump, 0x25 is a mod-r\m byte signifing that the operand of this instruction
				// is a 32bit displacement. in 64 bit mode, this displacement is actually RIP + 32bit Displacement
				// So 0xff 0x25 Displacement translets to: jmp qword ptr [rip + displacement]
				// So we will jump to the address stored at memory location "rip+displacement"

				// Our displacement is 0. This means that our instruction will be jmp qword ptr [rip]
				// rip always hold the memory address of the next instruction
				// So if our next instruction is not an instruction, but our operand address
				// We will get our needed absolute jump
				{ 0xff_b, 0x25_b, 0x00_b, 0x00_b, 0x00_b, 0x00_b},
				{ DWORD64_OPERAND }
			};
		}

	public:
		AssemblyCodeGenerator64()
		{
			// Jumps
			GeneratorMap.insert(std::make_pair(ECodeType::ABSOLUTE_JUMP_64, GenerateAbsoluteJump));
			GeneratorMap.insert(std::make_pair(ECodeType::RELATIVE_JUMP, GenerateRelativeJump));

			GeneratorMap.insert(std::make_pair(ECodeType::LOAD_DLL, GenerateLoadDllCode));
			GeneratorMap.insert(std::make_pair(ECodeType::MEMCOPY, GenerateMemCpyCode));
			GeneratorMap.insert(std::make_pair(ECodeType::VIRTUAL_PROTECT, GenerateVirtualProtectCode));
			GeneratorMap.insert(std::make_pair(ECodeType::FLUSH_INSTRUCTION, GenerateFlushInstructionsCode));

			// Push/pop
			GeneratorMap.insert(std::make_pair(ECodeType::PUSH_REGISTERS, GeneratePushAllRegisters));
			GeneratorMap.insert(std::make_pair(ECodeType::POP_REGISTERS, GeneratePopAllRegisters));
		}
	};

}