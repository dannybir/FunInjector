#pragma once

#include "pch.h"
#include "IAssemblyCodeGenerator.h"

namespace FunInjector
{
	class AssemblyCodeGenerator32 : public IAssemblyCodeGenerator
	{

		static AssemblyCode GenerateLoadDllCode()
		{
			return
			{
				// push Operand: Address to path to DLL
				{ 0x68_b, DWORD_OPERAND},

				// mov eax, Operand: Pointer to LoadLibrary function
				{ 0xb8_b,DWORD_OPERAND},

				// call eax
				{ 0xff_b, 0xd0_b },
			};
		}

		static AssemblyCode GenerateMemCpyCode()
		{
			return
			{
				// push Operand: Target Address
				{ 0x68_b, DWORD_OPERAND},

				// push Operand: Source Address
				{ 0x68_b, DWORD_OPERAND},

				// push Operand: Size to copy
				{ 0x68_b, DWORD_OPERAND},

				// mov eax, Operand: Pointer to function
				{ 0xb8_b, DWORD_OPERAND},

				// call eax
				{ 0xff_b, 0xd0_b },

				// add esp,12
				{ 0x83_b, 0xc4_b, 0xc_b },
			};
		}

		static AssemblyCode GenerateVirtualProtectCode()
		{
			return
			{
				// push Operand = Target Protect Address
				{ 0x68_b, DWORD_OPERAND},

				// push Operand = Size of Memory to protect
				{ 0x68_b, DWORD_OPERAND},

				// push Operand = New Protect Value
				{ 0x68_b, DWORD_OPERAND},

				// push esp
				{ 0x68_b, DWORD_OPERAND},

				// mov eax, Operand = Pointer to VirtualProtect
				{ 0xb8_b, DWORD_OPERAND},

				// call eax
				{ 0xff_b, 0xd0_b },
			};
		}

		static AssemblyCode GenerateFlushInstructionsCode()
		{
			return
			{
				// mov eax, Operand: Pointer to GetCurrentProcess function
				{ 0xb8_b, DWORD_OPERAND},

				// call eax ( GetCurrentProcess )
				{ 0xff_b, 0xd0_b },

				// push eax
				{ 0x50_b },

				// push Operand: Base address
				{ 0x68_b, DWORD_OPERAND},

				// push Operand: Size to copy
				{ 0x68_b, DWORD_OPERAND},

				// mov eax, Operand: Pointer to function
				{ 0xb8_b, DWORD_OPERAND},

				// call eax
				{ 0xff_b, 0xd0_b },
			};
		}

		static AssemblyCode GeneratePushAllRegisters()
		{
			return
			{
				{0x60_b},
			};
		}

		static AssemblyCode GeneratePopAllRegisters()
		{
			return
			{
				{0x61_b}
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

	public:
		AssemblyCodeGenerator32()
		{
			// Jumps
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