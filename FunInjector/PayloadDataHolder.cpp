#include "pch.h"
#include "PayloadDataHolder.h"

namespace FunInjector
{
	static auto DataTypeToByteBufferConverter = [](auto && Value, ByteBuffer& OutBuffer)
	{
		using Type = std::decay_t< decltype(Value)>;

		if constexpr (std::is_same_v< Type, ByteBuffer> )
		{
			OutBuffer = Value;
		}
		else
		{
			OutBuffer = TypeToBuffer(Value);
		}

	};

	void PayloadDataHolder::AddData(const std::wstring& Name, const DataType& Data) noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		DataList.push_back( std::make_pair(Name, Data) );

		HANDLE_EXCEPTION_END;
	}

	std::optional<DataType> PayloadDataHolder::GetDataByName(const std::wstring& Name) const noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		auto Iterator = std::find_if(DataList.cbegin(), DataList.cend(), [&](const auto& DataPair)
		{
			if (DataPair.first == Name)
			{
				return true;
			}
			else
			{
				return false;
			}
		});

		if (Iterator == DataList.end())
		{
			return std::nullopt;
		}
		
		return Iterator->second;

		HANDLE_EXCEPTION_END_RET(DataType());
	}

	DWORD64 PayloadDataHolder::GetDataLocationByName(const std::wstring& Name) const noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		if (PayloadBaseAddress == 0)
		{
			// Log this
			return 0;
		}

		// TODO: Cache this on insertion into map
		auto Offset = DWORD64 {0};
		for (const auto& [DataName, DataValue] : DataList)
		{
			// Increase offset between base address and what we are looking for
			if (DataName != Name)
			{
				Offset += static_cast<DWORD64>(GetDataTypeSize(DataValue));
			}
			else
			{
				break;
			}
		}

		return PayloadBaseAddress + Offset;

		HANDLE_EXCEPTION_END_RET(0);
	}

	SIZE_T PayloadDataHolder::GetTotalDataSize() const noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		// Expensive, but easiest for now
		// Will probably not be a major bottleneck
		return ConvertDataToBuffer().size();

		HANDLE_EXCEPTION_END_RET(0);
	}

	ByteBuffer PayloadDataHolder::ConvertDataToBuffer() const noexcept
	{
		HANDLE_EXCEPTION_BEGIN;

		ByteBuffer FinalBuffer;

		auto DataTypeConverter = [&](auto&& Value)
		{
			ByteBuffer DataBuffer;
			DataTypeToByteBufferConverter(Value, DataBuffer);
			AppendBufferToBuffer(FinalBuffer, DataBuffer);
		};

		for (const auto& [DataName, DataValue] : DataList)
		{
			std::visit( DataTypeConverter, DataValue );
		}

		return FinalBuffer;

		HANDLE_EXCEPTION_END_RET(ByteBuffer());
	}


	SIZE_T PayloadDataHolder::GetDataTypeSize(const DataType& Data) const
	{
		SIZE_T TotalSize = 0;

		auto DataTypeConverter = [&](auto && Value)
		{
			ByteBuffer DataBuffer;
			DataTypeToByteBufferConverter(Value, DataBuffer);
			TotalSize = DataBuffer.size();
		};

		std::visit(DataTypeConverter, Data);

		return TotalSize;
	}
}


