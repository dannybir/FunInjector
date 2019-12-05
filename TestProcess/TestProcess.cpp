

#include "pch.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <Windows.h>

#include <wil/resource.h>

using namespace std::chrono_literals;

int main()
{
	wil::unique_event_nothrow TriggerEvent;
	TriggerEvent.open(L"TriggerEvent");

	if (!TriggerEvent)
	{
		return -1;
	}

	TriggerEvent.wait(20000);
	TriggerEvent.reset();

	// Don't care if the function is successeful, just need to call it
	CreateFileW(L"", 0, 0, nullptr, 0, 0, nullptr);

	std::this_thread::sleep_for(3s);

	CreateFileW(L"", 0, 0, nullptr, 0, 0, nullptr);

	return 0;
}
