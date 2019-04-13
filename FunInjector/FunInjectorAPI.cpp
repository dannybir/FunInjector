// FunInjector.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include "FunInjectorAPI.h"

#include "FuncHookProcessInjector.h"

namespace FunInjector
{
	// TODO: This is an example of a library function
	void InjectDll()
	{
		static plog::ColorConsoleAppender<plog::TxtFormatter> ColorConsoleLogger;
		plog::init(plog::debug, &ColorConsoleLogger);

		FuncHookProcessInjector injector(1808, "c:/dll.dll", "KERNELBASE!CreateFileW");
		injector.PrepareForInjection();
		injector.InjectDll();
	}
}

