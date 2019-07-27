#pragma once

#include <string_view>
#include <string>
#include <sstream>
#include <exception>

// Logger
#include <plog/Log.h>
#include <plog/Appenders/ColorConsoleAppender.h>

namespace ErrorHandler
{
	class Exception : public std::runtime_error
	{
	public:
		Exception(
			const std::string_view Message,
			int LineNum,
			const std::string_view FuncFilePath,
			const std::string_view FuncName
		)
			:
			std::runtime_error(Message.data()),
			LineNumber(LineNum),
			FilePath(FuncFilePath),
			FunctionName(FuncName)
		{}

		inline std::string GetFormattedMessage() const
		{
			// Exceptions will be displayed in the following way:
			// \n
			// [*FunctionName* - *SourceFilePath*(*LineNumber*)]
			std::stringstream OutStringStream;
			OutStringStream << "\n[" << FunctionName << " - " << FilePath << "(" << LineNumber << ")" << "] " << what();

			return OutStringStream.str();
		}

	private:
		int LineNumber = 0;
		std::string FilePath;
		std::string FunctionName;
	};

	class ExceptionHandlerInstance
	{
	private:
		ExceptionHandlerInstance() {}

	public:
		// This is a singleton
		ExceptionHandlerInstance(const ExceptionHandlerInstance&) = delete;
		ExceptionHandlerInstance& operator=(const ExceptionHandlerInstance&) = delete;
		ExceptionHandlerInstance(ExceptionHandlerInstance&&) = delete;
		ExceptionHandlerInstance& operator=(ExceptionHandlerInstance&&) = delete;

		static auto& GetInstance() 
		{
			static ExceptionHandlerInstance ExceptionHandler;
			return ExceptionHandler;
		}

		void HandleException() const noexcept
		{
			try
			{
				throw;
			}
			catch (const Exception& Exception)
			{
				auto Message = "Exception caught: " + Exception.GetFormattedMessage();
				DisplayErrors(Message);

			}
			catch (const std::exception & GeneralException)
			{
				auto Message = "std::exception caught: " + std::string(GeneralException.what());
				DisplayErrors(Message);
			}
			catch (...)
			{
				DisplayErrors("General Exception caught");
			}
		}

		inline void ToggleUseMessageBox(bool Value) noexcept
		{
			ShouldUseMessageBox = Value;
		}

		inline void TogglePringLog(bool Value) noexcept
		{
			ShouldPrintLog = Value;
		}

		inline void SetHandlerName(const std::string_view InHandlerName) noexcept
		{
			HandlerName = InHandlerName;
		}

	private:
		void PrintLog(const std::string Message) const
		{
			if (ShouldPrintLog)
			{
				LOG_ERROR << "[" << HandlerName << "]" << Message;
			}
		}

		void ShowMessageBox(const std::string Message) const
		{
			if (ShouldUseMessageBox)
			{
				MessageBoxA(nullptr, Message.c_str(), "Exception caught!", MB_OK);
			}
		}

		void DisplayErrors(const std::string Message) const
		{
			PrintLog(Message);
			ShowMessageBox(Message);
		}

	private:
		bool ShouldUseMessageBox = false;
		bool ShouldPrintLog = true;

		std::string HandlerName;
	};

}

// Must use a define so that __FUNCTION__ , __FILE__ and __LINE__ preprocessor
#define THROW_EXCEPTION_MESSAGE( Message ) \
	throw ErrorHandler::Exception( Message, __LINE__, __FILE__, __FUNCTION__);

#define THROW_EXCEPTION_FORMATTED_MESSAGE( FormattedMessage ) \
	std::stringstream OutStringStream; \
	OutStringStream << FormattedMessage; \
	throw ErrorHandler::Exception( OutStringStream.str(), __LINE__, __FILE__, __FUNCTION__); 


#define HANDLE_EXCEPTION_BEGIN try {
#define HANDLE_EXCEPTION_END \
	} catch (...) \
	{ \
		ErrorHandler::ExceptionHandlerInstance::GetInstance().HandleException(); \
	}

#define HANDLE_EXCEPTION_END_RET(ReturnValue) \
	} catch (...) \
	{ \
		ErrorHandler::ExceptionHandlerInstance::GetInstance().HandleException(); \
		return ReturnValue; \
	}
