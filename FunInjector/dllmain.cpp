
#include "pch.h"

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		ExceptionHandler::ExceptionHandlerInstance::GetInstance().SetShouldCollectStackTrace(true);

		ExceptionHandler::ExceptionHandlerInstance::GetInstance().AddOnExceptionAction("LogOnException",
			[](auto Message) { LOG_ERROR << Message; });
		ExceptionHandler::ExceptionHandlerInstance::GetInstance().AddOnExceptionAction("MessageBoxOnException",
			[](auto Message) { MessageBoxA(nullptr, Message.data(), "Exception Thrown!", MB_OK); });

		static plog::ColorConsoleAppender<plog::TxtFormatter> ColorConsoleLogger;
		plog::init(plog::debug, &ColorConsoleLogger);
	}
	return TRUE;
}
