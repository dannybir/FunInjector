

#include "pch.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <Windows.h>

#include <wil/resource.h>

using namespace std::chrono_literals;

int main()
{
	std::this_thread::sleep_for(1s);

	return 0;
}
