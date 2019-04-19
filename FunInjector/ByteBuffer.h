#pragma once

#include "pch.h"

namespace FunInjector
{
	// Create an alias for a byte sized value for convininience
	using Byte = unsigned char;

	// All memory read or write function should return a byte buffer, which is just a std::vector of byte sized data type
	using ByteBuffer = std::vector< Byte >;

	// Create a little endian representation of some Integer value as a byte array
	template< typename IntegerType >
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
			StrStream << " " << std::hex << Byte << " ";
		}

		return StrStream.str();
	}
}