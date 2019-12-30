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
				// Prologue
				// push ebp
				// mov ebp, esp
				{ 0x55_b },
				{ 0x89_b, 0xe5_b },

				// sub esp, 54
				{ 0x83_b, 0xec_b, 0x36_b },

				// push Operand: Address to path to DLL
				{ 0x68_b, DWORD_OPERAND},

				// lea ecx,[ebp-0xa]
				{ 0x8d_b, 0x4d_b, 0xf6_b },

				// push ecx
				{ 0x51_b },

				// mov eax, Operand: Pointer to RtlInitUnicodeString function
				{ 0xb8_b, DWORD_OPERAND},

				// call eax
				{ 0xff_b, 0xd0_b },

				//  push OUT module handle = 0 
				{ 0x68_b, DWORD_OPERAND},

				// lea ecx,[ebp-0xa]
				{ 0x8d_b, 0x4d_b, 0xf6_b },

				// push ecx = Module path
				{ 0x51_b },

				// push PathToFilePtr = 0
				{ 0x68_b, DWORD_OPERAND},

				// push Operand = Flags = LOAD_WITH_ALTERED_SEARCH_PATH
				{ 0x68_b, DWORD_OPERAND},

				// mov eax, Operand: Pointer to LdrLoadDll function
				{ 0xb8_b, DWORD_OPERAND},

				// call eax
				{ 0xff_b, 0xd0_b },

				// add esp, 54 - Clear the unicode string
				{ 0x83_b, 0xc4_b, 0x36_b },

				// Epilogue 
				// mov esp, ebp
				// pop ebp
				{ 0x89_b, 0xec_b },
				{ 0x5d_b }
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
				// push pointer to Old protect value
				{ 0x68_b, DWORD_OPERAND},

				// push Operand = New Protect Value
				{ 0x68_b, DWORD_OPERAND},

				// push Operand = Size of Memory to protect
				{ 0x68_b, DWORD_OPERAND},

				// push Operand = Target Protect Address
				{ 0x68_b, DWORD_OPERAND},

				// GetCurrentProcess = (HANDLE-1) placed into eax
				{ 0x83_b, 0xc8_b, 0xff_b },

				// push eax
				{ 0x50_b },

				// mov eax, Operand = Pointer to NtProtectVirtualMemory
				{ 0xb8_b, DWORD_OPERAND},

				// call eax
				{ 0xff_b, 0xd0_b },
			};
		}

		static AssemblyCode GenerateFlushInstructionsCode()
		{
			return
			{
				// push Operand: Size to copy
				{ 0x68_b, DWORD_OPERAND},

				// push Operand: Base address
				{ 0x68_b, DWORD_OPERAND},

				// GetCurrentProcess = (HANDLE-1) placed into eax
				{ 0x83_b, 0xc8_b, 0xff_b },

				// push eax
				{ 0x50_b },

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