#pragma once

#include "pch.h"

namespace FunInjector
{
	using DataType = std::variant< std::wstring, ByteBuffer, int >;
	class PayloadDataHolder
	{

	public:
		PayloadDataHolder() = default;
		PayloadDataHolder(DWORD64 BaseAddress) : PayloadBaseAddress(BaseAddress) {}

		// Will add a data item to the list of items
		void AddData(const std::wstring& Name, const DataType& Data) noexcept;

		// Return a data type by its stored name, if not found, returns an empty optional
		std::optional<DataType> GetDataByName(const std::wstring& Name) const noexcept;

		// Returns a location of the data recognized by its name
		// Pay attention that this address will be real only when
		// the base address is set to a real address
		DWORD64 GetDataLocationByName(const std::wstring& Name) const noexcept;

		// Total size in bytes of all the data currently in this payload
		SIZE_T GetTotalDataSize() const noexcept;

		// Converts all the data inside this payload to one big buffer
		// which can then be written to the process
		ByteBuffer ConvertDataToBuffer() const noexcept;

		// 
		inline void SetBaseAddress(DWORD64 BaseAddress)
		{
			PayloadBaseAddress = BaseAddress;
		}

	private:
		SIZE_T GetDataTypeSize(const DataType& Data) const;

	private:
		// A list of objects with names that can be injected as payload to the target process
		// The target process injected assembly code can use data items from the payload
		// for various operations
		std::vector< std::pair< std::wstring, DataType >> DataList;

		// The base address where this payload data will sit in the target process
		DWORD64 PayloadBaseAddress = 0;
	};
}


