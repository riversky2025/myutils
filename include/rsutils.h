#ifndef RSUTILS
#define RSUTILS
#include <algorithm>
#include <chrono>
#include <iostream>
#include <ostream>
#include <string>
#include <vector>
#include <ctime>
#include <ccronexpr.h>
#include <queue>
#include <sstream>
#pragma comment(lib, "dbghelp.lib")
#define    WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <tchar.h>
#include <DbgHelp.h>
#include "nlohmann/json.hpp"
#include "httplib.h"
#include "spdlog/spdlog.h"
#include <spdlog/async.h>
#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/daily_file_sink.h"
#include "asio.hpp"
#ifdef UNICODE
#define TSprintf	wsprintf
#else
#define TSprintf	sprintf
#endif

#define BB_DEFAULT_SIZE 4096

namespace rs
{


	namespace design
	{
		template <class T>
		class singleton : private T
		{
		private:
			singleton();
			~singleton();

		public:
			static T& instance();
		};


		template <class T>
		inline singleton<T>::singleton()
		{
			/* no-op */
		}

		template <class T>
		inline singleton<T>::~singleton()
		{
			/* no-op */
		}

		template <class T>
		/*static*/ T& singleton<T>::instance()
		{
			// function-local static to force this to work correctly at static
			// initialization time.
			static singleton<T> s_oT;
			return(s_oT);
		}
	}




	namespace uuid
	{
		/**
		 *雪花算法
		 *Date :[7/10/2019 ]
		 *Author :[RS]
		 */
		class Snowflake
		{
		public:
			Snowflake() = default;
			~Snowflake() = default;
			void setEpoch(uint64_t epoch);
			void setMachine(int machine);
			/**
			 *生成策略
			 *Date :[7/10/2019 ]
			 *Author :[RS]
			 */
			uint64_t generate();
		private:
#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
#include <windows.h>
#include <time.h>
			uint64_t getTime();
#endif
			/**
			 *起始时间戳
			 *Date :[7/10/2019 ]
			 *Author :[RS]
			 */
			uint64_t epoch = 0;

			uint64_t time = 0;
			/**
			 *机器号
			 *Date :[7/10/2019 ]
			 *Author :[RS]
			 */
			int machine = 0;
			int sequence = 0;
		};

	}
	/**
	 * 性能时钟模块
	 */
	namespace clock
	{
		class TimerClock {
		public:
			TimerClock() : m_begin(std::chrono::high_resolution_clock::now()) {}
			void reset() { m_begin = std::chrono::high_resolution_clock::now(); }

			//默认输出毫秒
			int64_t elapsed() const;

			//输出秒
			int64_t elapsed_second() const;

			//微秒
			int64_t elapsed_micro() const;

			//纳秒
			int64_t elapsed_nano() const;



			//分
			int64_t elapsed_minutes() const;

			//时
			int64_t elapsed_hours() const;

		private:
			std::chrono::time_point<std::chrono::high_resolution_clock> m_begin;
		};
		class TimerClockFactory
		{
		public:
			static std::shared_ptr<TimerClock> getInstance();
		};
	}
	/**
	 * 字节数组
	 */
	namespace buffer
	{
		class ByteBuffer {
		public:
			ByteBuffer(uint32_t size = BB_DEFAULT_SIZE);
			~ByteBuffer();
			/**
			 * Returns the number of bytes (octets) this buffer can contain.
			 *Date :[7/29/2019 ]
			 *Author :[RS]
			 */
			uint32_t capacity(); // Size of internal vector


			/**
			 *清空数据，标记为全部置为0
			 *Date :[7/29/2019 ]
			 *Author :[RS]
			 */
			void clear();
			//Discards the bytes between the 0th index and readerIndex.markWR set0;
			ByteBuffer* discardReadBytes();

			//Returns the readerIndex of this buffer.
			uint32_t readerIndex();
			void readerIndex(uint32_t readerIndex) const;
			uint32_t writerIndex();
			void writerIndex(uint32_t writerIndex);

			bool setIndex(int readerIndex__, int writerIndex__);
			uint32_t readableBytes();
			uint32_t writableBytes();
			//当且仅当（this.writerIndex - this.readerIndex）大于0时返回true。
			bool  isReadable();
			//当且仅当此缓冲区包含等于或大于指定数量的元素时，才返回true。
			bool isReadable(int numBytes);
			//当且仅当（this.capacity - this.writerIndex）大于0时返回true。
			bool isWritable();
			//当且仅当此缓冲区有足够的空间允许写入指定数量的元素时，才返回true。
			bool 	isWritable(int numBytes);

			//标记此缓冲区中的当前readerIndex。
			ByteBuffer* markReaderIndex();
			//Repositions the current readerIndex to the marked readerIndex in this buffer.
			ByteBuffer* resetReaderIndex();
			//标记此缓冲区中的当前writerIndex。
			ByteBuffer* markWriterIndex();
			//Repositions the current writerIndex to the marked writerIndex in this buffer.
			ByteBuffer* resetWriterIndex();



			uint8_t* data();
			/**
			 *读指针
			 *Date :[9/27/2019 ]
			 *Author :[RS]
			 */
			uint8_t* dataReading();
			/**
			 *写指针
			 *Date :[9/27/2019 ]
			 *Author :[RS]
			 */
			uint8_t* dataWriting();
			/**
			 *读指针位置跳过skipStep
			 *Date :[9/27/2019 ]
			 *Author :[RS]
			 */
			bool skip(size_t skipStep);
			bool writeSkip(size_t skipStep);
			ByteBuffer* capacity(int newCapacity);

			/**
			 *字符串
			 *Date :[7/29/2019 ]
			 *Author :[RS]
			 */
			int32_t indexOf(uint32_t fromIndex, const char* key) {
				int32_t ret = -1;
				std::string b((char*)& buf[fromIndex], readableBytes());
				std::string findsub = key;
				auto res = b.find(findsub);
				if (res == std::string::npos) {
					return ret;
				}
				else {
					return res + fromIndex;
				}
			}
			//在此缓冲区中找到指定值的第一个匹配项.
			template<typename T>
			int32_t indexOf(T key) {
				int32_t ret = -1;

				for (uint32_t i = readerIndex_; i < writerIndex_; i++) {
					T data = read<T>(i);
					// Wasn't actually found, bounds of buffer were exceeded
					if ((key != 0) && (data == 0))
						break;
					// Key was found in array
					if (data == key) {
						ret = (int32_t)i;
						break;
					}
				}
				return ret;
			}
			//在此缓冲区中找到指定值的第一个匹配项.
			template<typename T>
			int32_t indexOf(uint32_t fromIndex, T key) {
				int32_t ret = -1;
				for (uint32_t i = fromIndex; i < writerIndex_; i++) {
					T data = read<T>(i);
					// Wasn't actually found, bounds of buffer were exceeded
					if ((key != 0) && (data == 0))
						break;

					// Key was found in array
					if (data == key) {
						ret = (int32_t)i;
						break;
					}
				}
				return ret;
			}
			// Replacement
			void replace(uint8_t key, uint8_t rep, uint32_t start = 0, bool firstOccuranceOnly = false)
			{
				for (uint32_t i = start; i < start + readableBytes(); i++) {
					uint8_t data = read<uint8_t>(i);
					// Wasn't actually found, bounds of buffer were exceeded
					if ((key != 0) && (data == 0))
						break;

					// Key was found in array, perform replacement
					if (data == key) {
						buf[i] = rep;
						if (firstOccuranceOnly)
							return;
					}
				}
			}

			// Read

			uint8_t get() const { // Relative get method. Reads the uint8_t at the buffers current position then increments the position
				return read<uint8_t>();
			}
			uint8_t get(uint32_t index) const { // Absolute get method. Read uint8_t at index
				return read<uint8_t>(index);
			}
			char getChar() const { // Relative
				return read<char>();

			}
			char getChar(uint32_t index) const { // Absolute
				return read<char>(index);
			}
			double getDouble() const
			{
				return read<double>();

			}
			double getDouble(uint32_t index) const
			{
				return read<double>(index);

			}
			float getFloat() const
			{
				return read<float>();
			}
			float getFloat(uint32_t index) const
			{
				return read<float>(index);

			}
			uint32_t getInt() const
			{
				return read<uint32_t>();

			}
			uint32_t getInt(uint32_t index) const
			{
				return read<uint32_t>(index);
			}
			uint64_t getLong() const
			{
				return read<uint64_t>();
			}
			uint64_t getLong(uint32_t index) const
			{
				return read<uint64_t>(index);
			}
			uint16_t getShort() const
			{
				return read<uint16_t>();
			}
			uint16_t getShort(uint32_t index) const
			{
				return read<uint16_t>(index);
			}

			// Write

			void put(ByteBuffer* src) { // Relative write of the entire contents of another ByteBuffer (src)
				uint32_t len = src->writerIndex_;
				for (uint32_t i = 0; i < len; i++)
					append<uint8_t>(src->get(i));
			}
			void put(uint8_t b) { // Relative write
				append<uint8_t>(b);
			}
			void put(uint8_t b, uint32_t index) { // Absolute write at index
				insert<uint8_t>(b, index);
			}
			void putBytes(const char* b) { // c string
				auto len = strlen(b);
				putBytes((uint8_t*)b, len);
			}
			void putBytes(uint8_t* b, uint32_t len) { // Relative write
				// Insert the data one byte at a time into the internal buffer at position i+starting index
				memcpy(&buf[writerIndex_], b, len);
				writerIndex_ += len;
			}
			void putBytes(uint8_t* b, uint32_t len, uint32_t index) { // Absolute write starting at index
				markWriterIndex_ = index;
				// Insert the data one byte at a time into the internal buffer at position i+starting index
				for (uint32_t i = 0; i < len; i++)
					append<uint8_t>(b[i]);
			}
			void putChar(char value) { // Relative
				append<char>(value);
			}
			void putChar(char value, uint32_t index) { // Absolute
				insert<char>(value, index);
			}
			void putDouble(double value)
			{
				append<double>(value);
			}
			void putDouble(double value, uint32_t index)
			{
				insert<double>(value, index);
			}
			void putFloat(float value)
			{
				append<float>(value);
			}
			void putFloat(float value, uint32_t index)
			{
				insert<float>(value, index);
			}
			void putInt(uint32_t value)
			{
				append<uint32_t>(value);
			}
			void putInt(uint32_t value, uint32_t index)
			{
				insert<uint32_t>(value, index);
			}
			void putLong(uint64_t value)
			{
				append<uint64_t>(value);
			}
			void putLong(uint64_t value, uint32_t index)
			{
				insert<uint64_t>(value, index);
			}
			void putShort(uint16_t value)
			{
				append<uint16_t>(value);
			}
			void putShort(uint16_t value, uint32_t index)
			{
				insert<uint16_t>(value, index);
			}


			//功能扩展,支持与其他asiobuf的接口转换


			// Utility Functions
			void printInfo()
			{
				std::cout << "info:0___markRd:" << markReaderIndex_ << "____read:" << readerIndex_
					<< "_____write:" << writerIndex_ << "_____markWrite:" << markWriterIndex_ << "_____capacity:" << capacity_ << std::endl;
			}
		protected:
			static bool checkIndexBounds(uint32_t readerIndex, uint32_t writerIndex, uint32_t capacity) {
				if (readerIndex < 0 || readerIndex > writerIndex || writerIndex > capacity) {
					return false;
				}
				else {
					return true;
				}
			}
			void adjustMarkers(int decrement) {
				if (markReaderIndex_ <= decrement) {
					markReaderIndex_ = 0;
					if (markWriterIndex_ <= decrement) {
						markWriterIndex_ = 0;
					}
					else {
						markWriterIndex_ -= decrement;
					}
				}
				else {
					markReaderIndex_ -= decrement;
					markWriterIndex_ -= decrement;
				}
			}

		private:
			mutable uint32_t writerIndex_;
			mutable uint32_t readerIndex_;
			mutable uint32_t markWriterIndex_;
			mutable uint32_t markReaderIndex_;
			mutable uint32_t capacity_;
			uint8_t* buf;


			/**
			 *调整markReaderIndex
			 *Date :[7/29/2019 ]
			 *Author :[RS]
			 */
			template<typename T> T read() const {
				T data = read<T>(markReaderIndex_);
				markReaderIndex_ += sizeof(T);
				return data;
			}

			template<typename T> T read(uint32_t index) const {
				if (index + sizeof(T) <= writerIndex_)
					return *((T*)& buf[index]);
				return 0;
			}

			template<typename T> void append(T data) {
				uint32_t s = sizeof(data);
				memcpy(&buf[writerIndex_], (uint8_t*)& data, s);
				//printf("writing %c to %i\n", (uint8_t)data, wpos);
				writerIndex_ += s;
			}

			template<typename T> void insert(T data, uint32_t index) {
				if ((index + sizeof(data)) > capacity_)
					return;

				memcpy(&buf[index], (uint8_t*)& data, sizeof(data));
				writerIndex_ = index + sizeof(data);
			}
		};

	}

	namespace JsonUtils
	{
		/*
		 * \brief 将指定文件目录的json格式,转成对象
		 * \tparam T
		 * \param filePath
		 * \param
		 * \return
		 */
		template<class T>
		static bool FileToClass(const std::string& filePath, T& value) {
			try {
				std::ifstream  input(filePath);
				nlohmann::json j;
				input >> j;
				value = j.get<T>();
				return true;
			}
			catch (const  std::exception& e)
			{
				std::cout << "error: " << filePath << ",detail" << e.what() << std::endl;
				std::this_thread::sleep_for(std::chrono::seconds(2));
				return false;
			}
		}
		/**
		 * \brief 将类转成json字符串
		 * \tparam T
		 * \param toString
		 * \param
		 * \return
		 */
		template<class T>
		static bool ClassToString(std::string& toString, const T& value) {
			try {
				T a{ value };
				nlohmann::json j(a);
				std::stringstream s;
				s << j.dump() << std::endl;
				toString = s.str();
				return true;
			}
			catch (const  std::exception& e)
			{
				std::cout << "ClassToString error: " << e.what() << std::endl;
				std::this_thread::sleep_for(std::chrono::seconds(2));
				return false;
			}
		}
		/**
		 * \brief 将字符串json转成类对象
		 * \tparam T
		 * \param src
		 * \param
		 * \return
		 */
		template<class T>
		static bool StringToClass(const std::string& src, T& tar) {
			try {
				std::stringstream  input(src);
				nlohmann::json j;
				input >> j;
				tar = j.get<T>();
				return true;
			}
			catch (const  nlohmann::json::exception& e)
			{
				std::cout << "targetType:" << typeid(tar).name() << ",StringToClass error: " << e.what() << std::endl;
				std::this_thread::sleep_for(std::chrono::microseconds(2));
				return false;
			}
		}
		/**
		 * \brief 将类对象转成持久化到filePath为名称的
		 * \tparam T 类模板
		 * \param filePath
		 * \param
		 * \return
		 */
		template<class T>
		static bool ClassToFile(const std::string& filePath, const  T& value) {
			try {
				nlohmann::json j(value);
				std::ofstream out(filePath);
				out << j.dump(2) << std::endl;
				return true;
			}
			catch (const  std::exception& e)
			{
				std::cout << "ClassToFile error: " << e.what() << std::endl;
				std::this_thread::sleep_for(std::chrono::seconds(2));
				return false;
			}
		}
	}

	/**
	 * \brief	字符串工具类
	 * \tparam
	 * \param
	 * \param
	 * \return
	 */
	namespace StringUtils
	{
		/**
		 * \brief 将yyyy-MM-ddTHH:mm:ss转换成time_t
		 * \tparam
		 * \param timeStr yyyy-MM-ddTHH:mm:ss格式字符串
		 * \param
		 * \return
		 */
		static inline time_t convFromStr(const std::string& timeStr) {
			int year, month, day, hour, minute, second;// 定义时间的各个int临时变量。
			sscanf(timeStr.data(), "%d-%d-%dT%d:%d:%d", &year, &month, &day, &hour, &minute, &second);
			std::tm timeinfo = std::tm();
			timeinfo.tm_year = year - 1900;   // year: 2000
			timeinfo.tm_mon = month - 1;      // month: january
			timeinfo.tm_mday = day;     // day: 1st
			timeinfo.tm_hour = hour;
			timeinfo.tm_min = minute;
			timeinfo.tm_sec = second;
			timeinfo.tm_isdst = 0;
			//tm转time_t
			return mktime(&timeinfo);
		}
		/**
		 * \brief	将time_t转成字符串
		 * \tparam
		 * \param tim time_t类型时间
		 * \param
		 * \return
		 */
		static inline std::string TimeToString(const time_t& tim) {
			auto timsss = std::localtime(&tim);
			std::stringstream sb;
			sb << timsss->tm_year + 1900 << '-' << timsss->tm_mon + 1 << '-' << timsss->tm_mday << 'T' << timsss->tm_hour << ":" << timsss->tm_min << ":" << timsss->tm_sec;
			return sb.str();
		}
		/**
		 * \brief 将字符串按照指定的分隔符进行分割
		 * \tparam  字符串
		 * \param str 待分割的字符串
		 * \param  分隔符
		 * \return 字符串数组
		 */
		static inline std::vector<std::string> Split(const std::string& str, const std::string& delim, const bool trim_empty = false) {
			size_t pos, last_pos = 0, len;
			std::vector<std::string> tokens;

			while (true) {
				pos = str.find(delim, last_pos);
				if (pos == std::string::npos) {
					pos = str.size();
				}

				len = pos - last_pos;
				if (!trim_empty || len != 0) {
					tokens.push_back(str.substr(last_pos, len));
				}

				if (pos == str.size()) {
					break;
				}
				else {
					last_pos = pos + delim.size();
				}
			}

			return tokens;
		}
		/**
		 * c类型字符串的按照指定分隔符进行分割
		 */
		static inline std::vector<std::string> Split(const char* strd, size_t length, const std::string& delim, const bool trim_empty = false) {
			std::string str(strd, length);
			return Split(str, delim, trim_empty);
		}
		/**
		 * 去除空串
		 */
		static inline std::vector<std::string> Compact(const std::vector<std::string>& tokens) {
			std::vector<std::string> compacted;
			for (size_t i = 0; i < tokens.size(); ++i) {
				if (!tokens[i].empty()) {
					compacted.push_back(tokens[i]);
				}
			}

			return compacted;
		}
		/**
		 * 按照指定字符串进行join
		 */
		static inline std::string Join(const std::vector<std::string>& tokens, const std::string& delim, const bool trim_empty = false) {
			if (trim_empty) {
				return Join(Compact(tokens), delim, false);
			}
			else {
				std::stringstream ss;
				for (size_t i = 0; i < tokens.size() - 1; ++i) {
					ss << tokens[i] << delim;
				}
				ss << tokens[tokens.size() - 1];

				return ss.str();
			}
		}
		/**
		 * 去除字符的换行符
		 */
		static inline std::string Trim(const std::string& str) {

			std::string blank = "\r\n\t ";
			size_t begin = str.size(), end = 0;
			for (size_t i = 0; i < str.size(); ++i) {
				if (blank.find(str[i]) == std::string::npos) {
					begin = i;
					break;
				}
			}

			for (size_t i = str.size(); i > 0; --i) {
				if (blank.find(str[i - 1]) == std::string::npos) {
					end = i - 1;
					break;
				}
			}

			if (begin >= end) {
				return "";
			}
			else {
				return str.substr(begin, end - begin + 1);
			}
		}
		/**
		 * 转大写
		 */
		static inline std::string ToUpper(const std::string& str) {
			std::string s(str);
			std::transform(s.begin(), s.end(), s.begin(), toupper);
			return s;
		}
		/**
		 * 转小写
		 */
		static inline std::string ToLower(const std::string& str) {
			std::string s(str);
			std::transform(s.begin(), s.end(), s.begin(), tolower);
			return s;
		}
		/**
		 * 获取路径分隔符
		 */
		static std::string PathSeparatorRS()
		{
#ifdef _WIN32
			return "\\";
#else
			return "/";
#endif
		}

		/**
		 *生成文件夹
		 */
		static bool CreateFolderRS(std::string strDir) {
#ifdef _WIN32
			return CreateDirectoryA(strDir.c_str(), NULL);
#else
			return mkdir(strDir.c_str(), 0700);
#endif
			return 0;
		}
		/**
		 * 获取文件生成路径
		 */
		static std::string getAppPathRS() {
#ifdef _WIN32
			char szPath[MAX_PATH];
			HMODULE hModule = ::GetModuleHandleA(".");
			::GetModuleFileNameA(hModule, szPath, MAX_PATH);
			char* find = strrchr(szPath, '\\');
			if (find) {
				*(find + 1) = 0;
			}
			return szPath;
#else
			char szPath[MAX_PATH];
			char* s = getcwd(szPath, MAX_PATH);
			strcat(szPath, "/");
			return szPath;
#endif
		}

	}
	/**
	 * 日志工具
	 *  三种工具函数
	 *  1. 控制台
	 *  2. 控制台+day file日志
	 *  3. 控制台+循环file日志
	 */
	namespace log
	{

		enum LogType
		{
			LOGCMD,
			LOGDAY,
			LOGROTATI
		};

		struct DayLogConfig
		{
			std::string logName = "system.log";
			int hour = 1;
			int min = 1;
			spdlog::level::level_enum fileLevel = spdlog::level::trace;
			spdlog::level::level_enum cmdLevel = spdlog::level::trace;
		};
		void to_json(nlohmann::json& j, const DayLogConfig& obj);
		void from_json(const nlohmann::json& j, DayLogConfig& obj);
		struct RotatingLogConfig
		{
			std::string logName = "system.log";
			int maxSize = 100;
			int fileNum = 3;
			spdlog::level::level_enum  fileLevel = spdlog::level::trace;
			spdlog::level::level_enum  cmdLevel = spdlog::level::trace;
		};
		void to_json(nlohmann::json& j, const RotatingLogConfig& obj);
		void from_json(const nlohmann::json& j, RotatingLogConfig& obj);


		typedef std::shared_ptr<spdlog::logger> LOGGER;
		extern std::once_flag onceFlag;


		class LoggerFactory
		{
		public:
			LoggerFactory();
			static LoggerFactory& getInstance();
			/**
			 * 控制台日志级别
			 */
			void init(spdlog::level::level_enum cmdLevel = spdlog::level::level_enum::trace);
			/**
		 * day日志
		 * 程序运行目录config/log.json
		 */
			void initDay();
			void initRotate();

		public:
			~LoggerFactory();
			/**
			 * 热更新日志级别
			 */
			void updateLogConfig(spdlog::level::level_enum cmdLevel, spdlog::level::level_enum fileLevel);
			/**
		 * 需要注意call_once 中决定启用的那种日志类型
		 */
			LOGGER getLogger(const char* loggername);
		private:
			DayLogConfig d;
			RotatingLogConfig config;
			std::vector<spdlog::sink_ptr> sinks;
		};
		inline  LOGGER getLogger(const char* loggername)
		{
			return LoggerFactory::getInstance().getLogger(loggername);
		}


	}/**
	 * 克隆表达式支持
	 */
	namespace quart
	{
		/**
		 * 正则表达式验证
		 */
		inline  bool getCornFormat(std::string const& cronStr, cron_expr& cornTmp)
		{
			const char* err;
			cron_parse_expr(cronStr.c_str(), &cornTmp, &err);
			return (err == NULL);
		}
		/**
		 * 获取正则表达式下一个time point
		 */
		inline bool getNextTimePoint(std::string const& cronStr, std::chrono::system_clock::time_point& result)
		{
			cron_expr cornTmp;
			memset(&cornTmp, 0, sizeof(cornTmp));
			auto next = time(NULL);
			if (getCornFormat(cronStr, cornTmp))
			{
				next = cron_next(&cornTmp, next);
				result = std::chrono::system_clock::from_time_t(next);
				return true;
			}
			else
			{
				return false;
			}


		}

	}
	/**
	 * web工具类
	 * 采用类restful api开发 ,嵌入文档,初始化需要传入配置
	 */
	namespace web
	{
		inline void CrosDomain(const httplib::Request& req, httplib::Response& res)
		{
			res.set_header("Access-Control-Allow-Origin", req.get_header_value("Origin").c_str());
			res.set_header("Allow", "GET, POST, HEAD, OPTIONS");
			res.set_header("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, Accept, Origin, Authorization");
			res.set_header("Access-Control-Allow-Methods", "OPTIONS, GET, POST, HEAD");
		}
		struct WebConf {
			//web path
			std::string path;
			//web ip
			std::string ip;
			//web port
			uint32_t port;
		};

		inline void from_json(const nlohmann::json& j, WebConf& p)
		{
			j.at("path").get_to(p.path);
			j.at("ip").get_to(p.ip);
			j.at("port").get_to(p.port);
		}

		inline void to_json(nlohmann::json& j, const WebConf& p)
		{
			j = nlohmann::json{ {"path",p.path},{"ip",p.ip},{"port",p.port} };
		}
		extern rs::log::LOGGER loggerWeb;

		class WebServer {
		public:
			WebServer();
			~WebServer();


			/**
			 *开始监听
			 *输入为config的路径,配置文件为web.json
			 *如果不配置,默认为"127.0.0.1:19527"
			 *Date :[7/10/2019 ]
			 *Author :[RS]
			 */
			void Start();
			void Stop();
			template<bool isGet>
			void Bind(std::string api, std::function<void(const httplib::Request&, httplib::Response&)> func)
			{

				if (isGet)
				{
					web.Get(api.c_str(), func);
				}
				else
				{
					web.Post(api.c_str(), func);
				}
			}
		private:
			/**
			 *初始化绑定
			 *Date :[7/10/2019 ]
			 *Author :[RS]
			 */
			void Init();

		private:
			rs::log::LOGGER loggerWeb = rs::log::getLogger("web");
			WebConf webConf;
			httplib::Server web;
		};
		void callOnceInstanceWeb();
		extern  std::shared_ptr<WebServer> webServer;
		extern std::once_flag onceFlagWeb;
		/**
		* 绑定get 或者post 方法(仅支持这两种)
		* 如果isGetFunc为ture,那么就是get方法,否则绑定post
		* 采用约定优于配置的方式,默认采用端口80,网页文件夹:web.在不采用配置文件的情况下
		*/
		template <bool  isGetFunc>
		void Bind(std::string apiPath, std::function<void(const httplib::Request&, httplib::Response&)> func)
		{
			if (!webServer)
			{
				std::call_once(onceFlagWeb, callOnceInstanceWeb);
			}
			webServer->Bind<isGetFunc>(apiPath, func);
		}
	}
	/**
	 * zabbix工具
	 */
	namespace zabbix
	{
		struct ResultString {
			bool result = false;
			std::string resultmsg = "";
			ResultString(bool res, std::string msg) :result(res), resultmsg(msg) {}
		};
		struct ZabbixConfig {
			std::string ZabbixHost;
			int ZabbixPort;
			std::string MonitoringHost;
			std::string MonitoringKey;
		};
		struct zabbixCoreData {
			std::string host;
			std::string key;
			std::string value;
		};
		struct zabbixData {
			std::string request = "sender data";
			std::vector<zabbixCoreData> data;
		};

		inline void from_json(const nlohmann::json& j, ZabbixConfig& p)
		{
			j.at("ZabbixHost").get_to(p.ZabbixHost);
			j.at("ZabbixPort").get_to(p.ZabbixPort);
			j.at("MonitoringHost").get_to(p.MonitoringHost);
			j.at("MonitoringKey").get_to(p.MonitoringKey);
		};

		inline void to_json(nlohmann::json& j, const  zabbixCoreData& p)
		{
			j = nlohmann::json{ {"host", p.host}, {"key", p.key}, {"value", p.value} };
		};

		inline void to_json(nlohmann::json& j, const zabbixData& p)
		{
			j = nlohmann::json{ {"request", p.request}, {"data", p.data} };
		};
		class ZbxSender
		{
		public:
			ZbxSender();
			std::atomic<bool> ready;

			void send(std::string data);

			~ZbxSender();
		private:
			void run();

			bool tcp_send(std::string value);
		private:
			std::shared_ptr<spdlog::logger> logger;
			std::queue<std::string> queue;
			std::string TextError;
			ZabbixConfig config;
		};


		void newInstanceCallOnce();

		void send(std::string msg);
	}
	/**
	 * dump处理
	 */
	namespace dumpbin
	{
		int GenerateMiniDump(PEXCEPTION_POINTERS pExceptionPointers);

		LONG WINAPI ExceptionFilter(LPEXCEPTION_POINTERS lpExceptionInfo);

	}

}

#endif /* RSUTILS */