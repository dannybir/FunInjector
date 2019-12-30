#pragma once

#include <dbghelp.h>
#include <string_view>
#include <string>
#include <sstream>
#include <exception>
#include <functional>

namespace ExceptionHandler
{
	// A general runtime exception with a bit more information
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

		// Exceptions will be displayed in the following format:
		// Exception thrown in function: @FunctionName
		// Source: @SourceFilePath, Line: @LineNumber
		// 
		// Stack trace:
		// ...
		inline std::string GetFormattedMessage() const noexcept
		{
			// Wouldn't want our exception to throw an exception :)
			// Swallow all possible exceptions, in that case
			// the formatted message will simply return the original message
			try
			{
				std::stringstream OutStringStream;
				OutStringStream << "\nException thrown in function:\t" << FunctionName;
				OutStringStream << "\nSource:\t" << FilePath.string() << ", Line: " << LineNumber;
				OutStringStream << "\nDescription: " << what();

				if (!BackTrace.empty())
				{
					OutStringStream << "\n\nStack trace:\n" << BackTrace;
				}
				return OutStringStream.str();
			}
			catch (...)
			{
				return what();
			}
		}

	// No point in restricting access here
	public:
		// Line number of the source file that the 'throw' occured on
		int LineNumber = 0;

		// File path of the source file the throw occured on
		std::filesystem::path FilePath;

		// The name of the function the 'throw' occured on
		std::string FunctionName;

		// A backtrace formatted string
		std::string BackTrace;

	};

	class StackTraceGenerator
	{
	public:
		StackTraceGenerator()
		{
			IsInitalized = SymInitialize(GetCurrentProcess(), nullptr, true);
		}
		~StackTraceGenerator()
		{
			SymCleanup(GetCurrentProcess());
		}

		// Will generate a stacktrace from the location of the call
		// This could throw, but if we call this, we are probably about to throw anyway
		std::string GenerateFormattedBacktrace() const noexcept
		{
			if (!IsInitalized)
			{
				return std::string("Cannot generate a stack trace properly, symbols not on!");
			}

			try
			{
				// The stack trace will looks like this for every frame:
				// [FrameNumber] ModuleName!FunctionName + Offset into function ( Will not try to get line information )
				// Or if function is not an exported symbol and there is no pdb
				// [FrameNubmer] ModuleName + Offset
				std::ostringstream BackTrace;

				constexpr auto MaximumFramesAmount = 125;
				std::array< PVOID, MaximumFramesAmount > StackFrames;

				// Dosent look this can fail, I guess if it does fail, the returned frame number is 0
				auto FrameNum = CaptureStackBackTrace(0, MaximumFramesAmount, StackFrames.data(), nullptr);
				for (int FrameIndex = 0; FrameIndex < FrameNum; FrameIndex++)
				{
					// This structure will hold more information regarding the address in the current frame
					// Because SYMBOL_INFO is weird, we must have a buffer big enough to hold the structure
					// and the function name.
					std::array< char, sizeof(SYMBOL_INFO) + (MAX_PATH + 1) * sizeof(char)> SymbolInfoBuffer;
					SYMBOL_INFO * Symbol = reinterpret_cast<SYMBOL_INFO*>(&SymbolInfoBuffer[0]);
					Symbol->MaxNameLen = MAX_PATH;
					Symbol->SizeOfStruct = sizeof(SYMBOL_INFO);

					auto AddressAtFrame = reinterpret_cast<DWORD64>(StackFrames[FrameIndex]);
					auto ModuleBase = SymGetModuleBase(GetCurrentProcess(), static_cast<DWORD>(AddressAtFrame));
					auto ModuleName = std::filesystem::path(GetModulePathByBase(ModuleBase)).filename().string();

					if (SymFromAddr(GetCurrentProcess(), AddressAtFrame, nullptr, Symbol))
					{
						std::string Function(MAX_PATH + 1, '\0');
						std::copy_n(std::begin(Symbol->Name), Symbol->NameLen, std::begin(Function));

						auto OffsetInFunction = AddressAtFrame - Symbol->Address;
						BackTrace << "[" << FrameIndex << "]:\t" << ModuleName << "!" << Function.c_str() << "+"
							<< "0x" << std::hex << OffsetInFunction << std::endl;
					}
					else
					{
						auto Offset = AddressAtFrame - ModuleBase;
						BackTrace << "[" << FrameIndex << "]:\t" << ModuleName << " + " << "0x" << std::hex << Offset << std::endl;
					}
				}

				return BackTrace.str();
			}
			catch (...)
			{
				// Just swallow any exception, if we cannot extract a stack trace for some reason
				// we'll just manage without one
				return "Not able to extract a stack trace";
			}	
		}

	private:
		// This function will return the path of the module based on it base address in memory
		std::string GetModulePathByBase(DWORD64 ModuleBase) const
		{
			std::array<char, MAX_PATH + 10> ModulePath;
			if (GetModuleFileNameA(reinterpret_cast<HMODULE>(ModuleBase), ModulePath.data(), MAX_PATH + 10) == 0)
			{
				return std::string("NoModuleFound");
			}
			return std::string(ModulePath.data());
		}

	private:
		bool IsInitalized = false;

	};

	// A single instance class which will handle exceptions
	// It will have a map of custom actions that will occur for every caught exception
	// The custom actions must be set on program initialization
	class ExceptionHandlerInstance
	{
		using OnExceptionAction = std::function< void(const std::string_view Message)>;
		using OnThrowAction = std::function< void(Exception& ExceptionObject)>;

	private:
		ExceptionHandlerInstance() {}

	public:
		// This is a singleton
		ExceptionHandlerInstance(const ExceptionHandlerInstance&) = delete;
		ExceptionHandlerInstance& operator=(const ExceptionHandlerInstance&) = delete;
		ExceptionHandlerInstance(ExceptionHandlerInstance&&) = delete;
		ExceptionHandlerInstance& operator=(ExceptionHandlerInstance&&) = delete;

		// Single instance
		static auto& GetInstance() noexcept
		{
			static ExceptionHandlerInstance ExceptionHandler;
			return ExceptionHandler;
		}

		// WARNING! This function must be called in a context where an exception already exists!
		// Calling OnException outside of a 'catch' statement will cause a program termination!

		// This method will rethrow the current active exception and then immideatly catch it
		// For every exception, a list of custom actions will be executed
		// Custom actions may include logging, showing a message box, collecting a stack trace, etc...
		void OnException() const noexcept
		{
			try
			{
				throw;
			}
			catch (const Exception& Exception)
			{
				ExecuteOnExceptionActions(Exception.GetFormattedMessage());
			}
			catch (const std::exception & GeneralException)
			{
				auto Message = "std::exception caught: " + std::string(GeneralException.what());
				ExecuteOnExceptionActions(Message);
			}
			catch (...)
			{
				ExecuteOnExceptionActions("General Exception caught");
			}
		}

		// This method is run by the Throw macro, it will receive an already created exception object
		// The registered custom actions will modify the exception object as they see fit if needed
		// and eventually, the macro will throw the object
		void OnThrow(Exception& ExceptionObject) const noexcept
		{
			try
			{
				if (ShouldCollectStackTrace)
				{
					ExceptionObject.BackTrace = BackTraceGenerator.GenerateFormattedBacktrace();
				}
				ExecuteOnThrowActions(ExceptionObject);
			}
			catch (...)
			{
				// Swallow everything, don't do any more custom operations when throwing this exception
			}
		}

		inline void SetShouldCollectStackTrace(bool Value) noexcept
		{
			ShouldCollectStackTrace = Value;
		}

		// Inserting to a map will now throw usually, unless there is some memory issues
		inline void AddOnExceptionAction(const std::string_view ActionName, OnExceptionAction Action)
		{
			OnExceptionActionMap.insert(std::make_pair(ActionName.data(), Action));
		}

		inline void AddOnThrowAction(const std::string_view ActionName, OnThrowAction Action)
		{
			OnThrowActionMap.insert(std::make_pair(ActionName.data(), Action));
		}

	private:
		void ExecuteOnExceptionActions(const std::string_view Message) const noexcept
		{
			try
			{
				for (const auto&[ActionName, Action] : OnExceptionActionMap)
				{
					Action(Message);
				}
			}
			catch (...)
			{
				// This must not throw any exceptions, as this will be called 
				// inside a catch statement itself
			}
		}

		void ExecuteOnThrowActions(Exception& ExceptionObj) const
		{
			for (const auto&[ActionName, Action] : OnThrowActionMap)
			{
				Action(ExceptionObj);
			}
		}

	private:
		// A map of actions ( function pointers ) that will run once an exception is caught
		// Each such action will receive the final message we would like to get from the exception
		std::unordered_map< std::string, OnExceptionAction > OnExceptionActionMap;

		// A map of actions that will run just before a throw will occur. This is more useful
		// for explicit throws where we can control how the exception object will look
		std::unordered_map< std::string, OnThrowAction > OnThrowActionMap;

		// This helps to generate stack traces for exceptions
		StackTraceGenerator BackTraceGenerator;

		// Will not collect stack traces on throws by default as it causes some overhead
		bool ShouldCollectStackTrace = false;
	};

}

// Must use a define so that __FUNCTION__ , __FILE__ and __LINE__ preprocessor
#define THROW_EXCEPTION_MESSAGE( Message ) \
	ExceptionHandler::Exception ExceptionObject( Message, __LINE__, __FILE__, __FUNCTION__);\
	ExceptionHandler::ExceptionHandlerInstance::GetInstance().OnThrow(ExceptionObject);\
	throw ExceptionObject;

#define THROW_EXCEPTION_FORMATTED_MESSAGE( FormattedMessage ) \
	std::stringstream OutStringStream; \
	OutStringStream << FormattedMessage; \
	THROW_EXCEPTION_MESSAGE(OutStringStream.str())


#define HANDLE_EXCEPTION_BEGIN try {
#define HANDLE_EXCEPTION_END \
	} catch (...) \
	{ \
		ExceptionHandler::ExceptionHandlerInstance::GetInstance().OnException(); \
	}

#define HANDLE_EXCEPTION_END_RET(ReturnValue) \
	} catch (...) \
	{ \
		ExceptionHandler::ExceptionHandlerInstance::GetInstance().OnException(); \
		return ReturnValue; \
	}
