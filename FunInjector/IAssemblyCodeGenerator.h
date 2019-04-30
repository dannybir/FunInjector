#pragma once

#include "pch.h"
#include "AssemblyCode.h"

namespace FunInjector
{
	enum class ECodeType
	{
		RELATIVE_JUMP,
		ABSOLUTE_JUMP_64, // Only supported in 64bit mode
		MEMCOPY,
		VIRTUAL_PROTECT,
		FLUSH_INSTRUCTION,
		LOAD_DLL,
		PUSH_REGISTERS,
		POP_REGISTERS
	};

	class IAssemblyCodeGenerator
	{
	public:
		IAssemblyCodeGenerator() = default;
		virtual ~IAssemblyCodeGenerator() {}

		//
		std::unordered_map< ECodeType, std::function< AssemblyCode() >> GeneratorMap;


	};
}
