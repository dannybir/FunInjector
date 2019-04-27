#pragma once

#include "pch.h"

namespace FunInjector
{
	// Create an alias for a byte sized value for convininience
	using Byte = std::byte;

	// All memory read or write function should return a byte buffer, which is just a std::vector of byte sized data type
	using ByteBuffer = std::vector< Byte >;

	// Create a little endian representation of some Integer value as a byte array
	template< typename IntegerType > // requires Integral< IntegerType >
	static ByteBuffer IntegerToByteBuffer(IntegerType Integer)
	{
		static_assert(std::is_integral_v< IntegerType >, "Supplied type to IntegerToByteBuffer is not an integral type");

		ByteBuffer IntegerBuffer;
		auto IntegerSize = sizeof(IntegerType);

		for (int ByteIndex = 0; ByteIndex < IntegerSize; ByteIndex++)
		{
			// Shift right by a byte, then mask everything apart from the LSB byte
			Byte ByteVal = static_cast<Byte>( (Integer >> 8 * ByteIndex) & 0xFF );
			IntegerBuffer.push_back(ByteVal);
		}

		return IntegerBuffer;
	}

	template< typename StringType > // requires Range< StringType >
	static ByteBuffer StringToByteBuffer(StringType&& String)
	{
		static_assert(std::is_same_v< StringType, std::string>, "Supplied type is not a std::string!");

		ByteBuffer StringBuffer(String.begin(), String.end());
		StringBuffer.push_back(static_cast<std::byte>('\0'));

		return StringBuffer;
	}

	template< typename Type >
	static ByteBuffer TypeToBuffer(Type&& Value)
	{
		if constexpr (std::is_same_v < Type, std::string)
		{
			return StringToByteBuffer(std::forward< Type >(Value));
		}
		else if constexpr (std::is_integral_v< Type >)
		{
			return IntegerToByteBuffer(Value);
		}
		else
		{
			static_assert("Supplied the wrong type, has to be either a std::string or an intergral type");
		}
	}

	// Takes an integer, turns it into a byte array and appends to supplied buffer
	template< typename IntegerType >
	static void AppendIntegerToBuffer(ByteBuffer& Buffer, IntegerType Integer)
	{
		auto IntegerBuffer = IntegerToByteBuffer(Integer);
		Buffer.insert(std::end(Buffer), std::begin(IntegerBuffer), std::end(IntegerBuffer));
	}

	// Append a buffer to the end of another
	static void AppendBufferToBuffer(ByteBuffer& Target, const ByteBuffer& Source)
	{
		Target.insert(Target.end(), Source.cbegin(), Source.cend());
	}


	static std::string BufferToString(const ByteBuffer& Buffer)
	{
		std::ostringstream StrStream;

		for (const auto& Byte : Buffer)
		{
			StrStream << " " << std::hex << static_cast<int>(Byte) << " ";
		}

		return StrStream.str();
	}
}