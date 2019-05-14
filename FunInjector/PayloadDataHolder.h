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

		void AddData(const std::wstring& Name, const DataType& Data);

		std::optional<DataType> GetDataByName(const std::wstring& Name) const;

		DWORD64 GetDataLocationByName(const std::wstring& Name) const;

		SIZE_T GetTotalDataSize() const;

		ByteBuffer ConvertDataToBuffer() const;

		inline void SetBaseAddress(DWORD64 BaseAddress)
		{
			PayloadBaseAddress = BaseAddress;
		}

	private:
		SIZE_T GetDataTypeSize(const DataType& Data) const;

	private:
		std::vector< std::pair< std::wstring, DataType >> DataList;

		DWORD64 PayloadBaseAddress = 0;
	};
}


