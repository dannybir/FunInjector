#pragma once

#include "AssemblyCode.h"
#include "pch.h"

namespace FunInjector
{
	class AssemblyCodeManager
	{
	public:
		AssemblyCodeManager();
		~AssemblyCodeManager();

		void AddAssemblyCode(const std::string_view Name, const AssemblyCode& Code) noexcept;


	private:
		std::unordered_map< std::string, AssemblyCode > AssemblyCodeMap;
	};

}


