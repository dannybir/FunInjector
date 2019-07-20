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
				// mov rcx, Operand: Address to path to DLL
				{ 0x48_b,0xb9_b, DWORD64_OPERAND},

				// mov rdi, Operand: Pointer to LoadLibrary function
				{ 0x48_b,0xbf_b,DWORD64_OPERAND},

				// sub rsp,54
				{ 0x48_b, 0x83_b, 0xec_b, 0x28_b},

				// call rdi
				{ 0xff_b, 0xd7_b },

				// add rsp,54
				{ 0x48_b, 0x83_b, 0xc4_b, 0x28_b },
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
				// mov r9, Operand Old protect pointer
				{ 0x49_b, 0xb9_b, DWORD64_OPERAND},

				// mov r8, Operand = New Protect Value
				{ 0x49_b, 0xc7_b, 0xc0_b, DWORD_OPERAND},

				// mov rdx, Operand = Size of Memory to protect
				{ 0x48_b, 0xc7_b, 0xc2_b, DWORD_OPERAND},

				// mov rcx, Operand = Target Protect Address
				{ 0x48_b, 0xb9_b, DWORD64_OPERAND},

				// mov rdi, Operand = Pointer to VirtualProtect
				{ 0x48_b, 0xbf_b, DWORD64_OPERAND},

				// sub rsp,54
				{ 0x48_b, 0x83_b, 0xec_b, 0x36_b},

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
				// mov rdi, Operand: Pointer to GetCurrentProcess function
				{ 0x48_b, 0xbf_b, DWORD64_OPERAND},

				// call rdi ( GetCurrentProcess )
				{ 0xff_b, 0xd7_b },

				// mov rcx, rax
				{ 0x48_b, 0x89_b, 0xc1_b},

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

				// sub rsp,54
				//{ 0x48_b, 0x83_b, 0xec_b, 0x36_b}
			};
		}

		static AssemblyCode GeneratePopAllRegisters()
		{
			return
			{
				// add rsp,54
				//{ 0x48_b, 0x83_b, 0xc4_b, 0x36_b },

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