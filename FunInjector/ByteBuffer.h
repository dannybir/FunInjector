#pragma once

#include "pch.h"

namespace FunInjector
{
	// Create an alias for a byte sized value for convininience
	using Byte = unsigned char;

	// All memory read or write function should return a byte buffer, which is just a std::vector of byte sized data type
	using ByteBuffer = std::vector< Byte >;

	// Create a little endian representation of some Integer value as a byte array
	template< typename IntegerType > // requires Integral< IntegerType >
	static ByteBuffer IntegerToByteBuffer(IntegerType Integer)
	{
		static_assert(std::is_integral_v< IntegerType >, "Supplied type to IntegerToByteBuffer is not an integral type");

		ByteBuffer IntegerBuffer;
		auto IntegerSize = sizeof(IntegerType);

		for (unsigned int ByteIndex = 0; ByteIndex < IntegerSize; ByteIndex++)
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

	template< typename StringType > // requires Range< StringType >
	static ByteBuffer StringToByteBuffer(StringType&& String)
	{
		static_assert(std::is_same_v< std::decay_t<StringType>, std::wstring>, "Supplied type is not a std::wstring!");

		std::vector< wchar_t > StringBuffer(String.begin(), String.end());
		StringBuffer.push_back(L'\0');

		ByteBuffer OutBuffer;
		for (auto Char : StringBuffer)
		{
			AppendIntegerToBuffer(OutBuffer, Char);
		}

		return OutBuffer;
	}

	template< typename Type >
	static ByteBuffer TypeToBuffer(Type&& Value)
	{
		// Remove qualifiers
		using T = std::decay_t<Type>;

		if constexpr (std::is_same_v < T, std::wstring>)
		{
			return StringToByteBuffer(std::forward< Type >(Value));
		}
		else if constexpr (std::is_integral_v< T >)
		{
			return IntegerToByteBuffer(Value);
		}
		else
		{
			static_assert(false ,"Supplied the wrong type, has to be either a std::wstring or an intergral type");
		}
	}

	// Append a buffer to the end of another
	static void AppendBufferToBuffer(ByteBuffer& Target, const ByteBuffer& Source)
	{
		Target.insert(Target.end(), Source.cbegin(), Source.cend());
	}

	template <typename CharType>
	static std::basic_string< CharType, std::char_traits<CharType>, std::allocator<CharType>>
		BufferToString(const ByteBuffer& Buffer)
	{
		
		using StringStream = std::basic_ostringstream< CharType, std::char_traits<CharType>, std::allocator<CharType>>;

		StringStream StrStream;
		for (const auto& Byte : Buffer)
		{
			StrStream << static_cast<CharType>(Byte);
		}

		return StrStream.str();
	}
}