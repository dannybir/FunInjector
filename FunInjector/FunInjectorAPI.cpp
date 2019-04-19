// FunInjector.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include "FunInjectorAPI.h"

#include "FuncHookProcessInjector.h"
#include "AssemblyCode.h"

namespace FunInjector
{
	using namespace Literals;
	// TODO: This is an example of a library function
	void InjectDll()
	{
		static plog::ColorConsoleAppender<plog::TxtFormatter> ColorConsoleLogger;
		plog::init(plog::debug, &ColorConsoleLogger);

		//FuncHookProcessInjector injector(104, "c:/dll.dll", "KERNELBASE!CreateFileW");
		//injector.PrepareForInjection();
		//injector.InjectDll();

		//AssemblyCode code({ {'\x01'_b,'\x01'_b, '\x02'_b ,0x0000ul}, { '\x01'_b,'\x01'_b, '\x02'_b, 0xc0d0ul} });

		AssemblyCode code(
			{ 
				{ 0x48_b,0xb9_b, DWORD64_OPERAND}, 
				{ 0x48_b,0xba_b, DWORD64_OPERAND},
				{ 0x49_b,0xc7_b,0xc0_b, DWORD_OPERAND},
				{ 0x48_b,0xbf_b,DWORD64_OPERAND},
				{ 0xff_b, 0xd7_b }
			});

		code.ModifyOperandsInOrder({ 
									{ 0x11_dw64 },
									{ 0x12_dw64 },
									{ 0x13_dw },
									{ 0x14_dw64 }
									});

		LOG_INFO << L"Code size: " << code.GetCodeSize();
	}
}

