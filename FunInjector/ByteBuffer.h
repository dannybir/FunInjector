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
	ByteBuffer IntegerToByteBuffer(IntegerType Integer)
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

}