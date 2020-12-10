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
#ifdef _WIN32
#include <Windows.h>
#include <tchar.h>
#include <DbgHelp.h>
#endif



#include <typeindex>
#include <memory>
#include <typeindex>
#include <exception>
#include <iostream>
#include <functional>
#include <type_traits>
#include <tuple>
#include "nlohmann/json.hpp"
#include "httplib.h"
#include "spdlog/spdlog.h"
#include <spdlog/async.h>
#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "spdlog/sinks/daily_file_sink.h"
#include "asio.hpp"
#include "concurrentqueue/blockingconcurrentqueue.h"
#include <atomic>
#ifdef UNICODE
#define TSprintf	wsprintf
#else
#define TSprintf	sprintf
#endif

#define BB_DEFAULT_SIZE 4096

namespace rs
{

	struct Any
	{
		Any(void) : m_tpIndex(std::type_index(typeid(void))) {}
		Any(const Any& that) : m_ptr(that.Clone()), m_tpIndex(that.m_tpIndex) {}
		Any(Any&& that) : m_ptr(std::move(that.m_ptr)), m_tpIndex(that.m_tpIndex) {}

		//创建智能指针时，对于一般的类型，通过std::decay来移除引用和cv符，从而获取原始类型
		template<typename U, class = typename std::enable_if<!std::is_same<typename std::decay<U>::type, Any>::value, U>::type> Any(U&& value) : m_ptr(new Derived < typename std::decay<U>::type>(std::forward<U>(value))),
			m_tpIndex(std::type_index(typeid(typename std::decay<U>::type))) {}

		bool IsNull() const { return !bool(m_ptr); }

		template<class U> bool Is() const
		{
			return m_tpIndex == std::type_index(typeid(U));
		}

		//将Any转换为实际的类型
		template<class U>
		U& AnyCast()
		{
			if (!Is<U>())
			{
				std::cout << "can not cast " << typeid(U).name() << " to " << m_tpIndex.name() << std::endl;
				throw std::logic_error{ "bad cast" };
			}

			auto derived = dynamic_cast<Derived<U>*> (m_ptr.get());
			return derived->m_value;
		}

		Any& operator=(const Any& a)
		{
			if (m_ptr == a.m_ptr)
				return *this;

			m_ptr = a.Clone();
			m_tpIndex = a.m_tpIndex;
			return *this;
		}

		Any& operator=(Any&& a)
		{
			if (m_ptr == a.m_ptr)
				return *this;

			m_ptr = std::move(a.m_ptr);
			m_tpIndex = a.m_tpIndex;
			return *this;
		}

	private:
		struct Base;
		typedef std::unique_ptr<Base> BasePtr;

		struct Base
		{
			virtual ~Base() {}
			virtual BasePtr Clone() const = 0;
		};

		template<typename T>
		struct Derived : Base
		{
			template<typename U>
			Derived(U&& value) : m_value(std::forward<U>(value)) { }

			BasePtr Clone() const
			{
				return BasePtr(new Derived<T>(m_value));
			}

			T m_value;
		};

		BasePtr Clone() const
		{
			if (m_ptr != nullptr)
				return m_ptr->Clone();

			return nullptr;
		}

		BasePtr m_ptr;
		std::type_index m_tpIndex;
	};
	class NonCopyable
	{
	public:
		NonCopyable(const NonCopyable&) = delete; // deleted
		NonCopyable& operator = (const NonCopyable&) = delete; // deleted
		NonCopyable() = default;   // available
	};
	namespace traits {
		//转换为std::function和函数指针. 
		template<typename T>
		struct function_traits;
		//普通函数.
		template<typename Ret, typename... Args>
		struct function_traits<Ret(Args...)>
		{
		public:
			enum { arity = sizeof...(Args) };
			typedef Ret function_type(Args...);
			typedef Ret return_type;
			using stl_function_type = std::function<function_type>;
			typedef Ret(*pointer)(Args...);

			template<size_t I>
			struct args
			{
				static_assert(I < arity, "index is out of range, index must less than sizeof Args");
				using type = typename std::tuple_element<I, std::tuple<Args...>>::type;
			};

			typedef std::tuple<std::remove_cv_t<std::remove_reference_t<Args>>...> tuple_type;
			typedef std::tuple<std::remove_const_t<std::remove_reference_t<Args>>...> bare_tuple_type;
		};
		//函数指针.
		template<typename Ret, typename... Args>
		struct function_traits<Ret(*)(Args...)> : function_traits<Ret(Args...)> {};

		//std::function.
		template <typename Ret, typename... Args>
		struct function_traits<std::function<Ret(Args...)>> : function_traits<Ret(Args...)> {};

		//member function.
#define FUNCTION_TRAITS(...)\
		template <typename ReturnType, typename ClassType, typename... Args>\
		struct function_traits<ReturnType(ClassType::*)(Args...) __VA_ARGS__> : function_traits<ReturnType(Args...)>{};\

		FUNCTION_TRAITS()
			FUNCTION_TRAITS(const)
			FUNCTION_TRAITS(volatile)
			FUNCTION_TRAITS(const volatile)
			//函数对象.
			template<typename Callable>
		struct function_traits : function_traits<decltype(&Callable::operator())> {};

		template <typename Function>
		typename function_traits<Function>::stl_function_type to_function(const Function& lambda)
		{
			return static_cast<typename function_traits<Function>::stl_function_type>(lambda);
		}

		template <typename Function>
		typename function_traits<Function>::stl_function_type to_function(Function&& lambda)
		{
			return static_cast<typename function_traits<Function>::stl_function_type>(std::forward<Function>(lambda));
		}

		template <typename Function>
		typename function_traits<Function>::pointer to_function_pointer(const Function& lambda)
		{
			return static_cast<typename function_traits<Function>::pointer>(lambda);
		}
	};

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

	namespace msgbus
	{
		class message_bus
		{
		public:
			template<typename Function>
			void RegisterHandler(std::string const& name, const Function& f)
			{
				using std::placeholders::_1;
				using std::placeholders::_2;
				using return_type=typename traits::function_traits<Function>::return_type;
				this->invokers_[name] = { std::bind(&invoker<Function>::apply,f,_1,_2) };
			}
			template<typename T, typename ...Args>
			T call(const std::string& name, Args&& ... args)
			{
				auto it = invokers_.find(name);
				if (it == invokers_.end())
				{
					return {};
				}
				auto args_tuple = std::make_tuple(std::forward<Args>(args)...);
				char data[sizeof(std::tuple < Args ...>)];
				std::tuple<Args...>* tp = new(data) std::tuple<Args...>;
				*tp = args_tuple;
				T t;
				it->second(tp, &t);
				return t;
			}
			template<typename ...Args>
			void call_void(const std::string& name, Args&& ... args)
			{
				auto it = invokers_.find(name);
				if (it == invokers_.end())
					return;
				auto args_tuple = std::make_tuple(std::forward<Args>(args)...);
				it->second(&args_tuple, nullptr);


			}
		private:
			template<typename Function>
			struct invoker
			{
				static inline void apply(const Function& func, void* b1, void* result)
				{
					using tuple_type=typename traits::function_traits<Function>::tuple_type;
					const tuple_type* tp = static_cast<tuple_type*>(b1);
					call(func, *tp, result);
				}
				template<typename F, typename ... Args>
				static typename std::enable_if<std::is_void<typename  std::result_of<F(Args...)>::type>::value>::type
					call(const F& f, const std::tuple<Args...>& tp, void*)
				{
					callHelp(f, std::make_index_sequence<sizeof ...(Args)>{}, tp);
				}
				template<typename F, typename ...Args>
				static typename std::enable_if<!std::is_void<typename  std::result_of<F(Args...)>::type>::value>::type
					call(const F& f, const std::tuple<Args...>& tp, void* result)
				{
					auto r = callHelp(f, std::make_index_sequence<sizeof ...(Args)>{}, tp);
					*(decltype(r)*)result = r;
				}
				template<typename F, size_t... I, typename ... Args>
				static auto callHelp(const F& f, const std::index_sequence<I...>&, const std::tuple<Args...>& tup)
				{
					return f(std::get<I>(tup)...);
				}
			};
		private:
			std::map<std::string, std::function<void(void*, void*)>> invokers_;
		};
	};
    namespace socket
    {
        /**
         * 编码类型
         */
        enum MSG_DIRECT
        {
            ENCODE,
            DECODE
        };
        namespace tcp
        {
            struct TcpConfAsio {
                std::string  ip;
                uint16_t port;
                uint8_t softwareVersion;
                uint8_t reConnectTime = 1;//连接失败重连时间间隔
                uint8_t heartBeat = 8;
            };
            enum TcpClientStatus
            {
                CONNECTING,
                DISCONNECING,
                CONNECTED,
                DISCONNECTED,
                CLOSED
            };

#define TRADER_SYSTEM_UTIL_TCPCLIENT_DEFAULT_RX_BUFFER_SIZE 8192
#define TRADER_SYSTEM_UTIL_TCPCLIENT_DEFAULT_TX_BUFFER_SIZE 8192
#define			MAX_MSG_SIZE_DEFAULT  1024
            class TcpClientI;
            struct Msg
            {
                std::string msgType;
                rs::Any     msg;
            };
            /**
             * 处理TCP
             * 注册心跳机制编码器,msgType 为heartbeat,触发的话1. 注册编码,2. 心跳间隔>0
             * msgType length 为消息长度与msgType 解析
             */
            template <unsigned int RxBufferSize = TRADER_SYSTEM_UTIL_TCPCLIENT_DEFAULT_RX_BUFFER_SIZE, unsigned int TxBufferSize = TRADER_SYSTEM_UTIL_TCPCLIENT_DEFAULT_TX_BUFFER_SIZE, unsigned int MAX_MSG_SIZE = MAX_MSG_SIZE_DEFAULT>
            class TcpClientImpl :public std::enable_shared_from_this<TcpClientImpl<RxBufferSize, TxBufferSize, MAX_MSG_SIZE>>
            {
            public:
                TcpClientImpl(TcpConfAsio config) :
                        tcpConfig(config),
                        ioThread(nullptr),
                        receiveBuffer(RxBufferSize), sendBuffer(TxBufferSize),
                        socket(ioContext), endpoint(asio::ip::address::from_string(config.ip), config.port),
                        timer(ioContext), inited(true)
                {
                    sending.store(false);
                    receiving.store(false);
                    connectHandle = [&](const auto ec) {
                        if (ec)
                        {
                            if (state_ == CONNECTED)
                            {
                                handler->onConnectionFailure(this->shared_from_this(), ec);
                            }
                            state_ = DISCONNECTED;
                            std::this_thread::sleep_for(std::chrono::seconds(tcpConf_.reConnectTime));
                            doReConnect();
                        }
                        else {
                            state_ = CONNECTED;
                            zbx.send("md center connect success");
                            OnConnect();
                            doRead();
                        }

                        if (ec)
                        {
                            status=DISCONNECTED;

                            std::this_thread::sleep_for(std::chrono::seconds(tcpConfig.reConnectTime));
                            doConnect();
                        }
                        else
                        {
                            handler->onConnected(this->shared_from_this());
                            if (tcpConfig.heartBeat > 0)
                            {
                                StartHeartBeat();
                            }
                            {
                                std::lock_guard<std::mutex> lock(mutexSocket);
                                status = CONNECTED;
                                receiving.store(false);
                                StartReceive();
                            }
                        }

                    };
                    sendHandle = [&](const auto& ec, auto size) {

                        std::lock_guard<std::mutex> lock(sendMutex);

                        if (ec)
                        {
                            handler->onSendError(this->shared_from_this(), ec);
                            if (status != CONNECTING)
                            {
                                doReconnect();
                            }
                            return;
                        }
                        handler->onSendComplete(this->shared_from_this(), sendBuffer.dataReading(), writeSize);
                        sendBuffer.skip(writeSize);
                        if (sendBuffer.readableBytes() > 0)
                        {
                            sending.store(false);
                            if (sendBuffer.writableBytes() < MAX_MSG_SIZE)
                            {
                                sendBuffer.discardReadBytes();
                            }
                            sendTx();
                        }
                        else
                        {
                            sendBuffer.discardReadBytes();
                            sending.store(false);
                        }


                        if (ec)
                        {
                            logger->error("write Error:{},{}", ec.value(), ec.message());
                            doConnect();
                        }
                        else {
                            bool sendFlag = false;
                            {
                                std::string tmp((char*)sendBuf->dataReading(), size);
                                logger->debug("[Send] {}", tmp);

                                sendBuf->skip(size);
                                //sendBuf->printInfo();
                                if (sendBuf->isReadable()) {
                                    doSend();
                                }
                                else {
                                    sendBuf->discardReadBytes();
                                    //sendBuf->printInfo();
                                }
                            }
                        }
                    };
                    readHandle = [&](const auto& ec, auto size) {
                        if (ec)
                        {
                            handler->onReceiveError(this->shared_from_this(), ec);
                            doConnect();
                        }
                        else
                        {
                            receiveBuffer.writeSkip(readSize);
                            if (receiveBuffer.writableBytes() < MAX_MSG_SIZE)
                            {
                                receiveBuffer.discardReadBytes();
                            }
                            int length;
                            auto msgType = decodes.call<std::string>("length", &receiveBuffer, &length);
                            if (receiveBuffer.readableBytes() >= length)
                            {
                                auto result = decodes.call<Any>(msgType, &receiveBuffer);
                                handler->onReceiveMsg(this->shared_from_this(), msgType, result);
                                receiveBuffer.skip(length);
                            }

                            doRead();
                        }
                    };

                }
                ~TcpClientImpl()
                {
                    Stop();
                    ioContext.stop();
                    if (ioThread->joinable())
                    {
                        ioThread->join();
                    }
                }
                void Start()
                {

                    {
                        std::lock_guard<std::mutex> lock(mutexSocket);
                        if (ioThread != nullptr)
                        {
                            return;
                        }
                    }
                    doConnect();
                    sendThread = new std::thread(std::bind(&TcpClientImpl::sendWork, this->shared_from_this()));

                    ioThread = new std::thread(std::bind(&TcpClientImpl::worker, this->shared_from_this()));

                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
                void Stop()
                {
                    inited = false;
                    if(status!=CLOSED){
                        status=CLOSED;
                    }
                    if (sendThread->joinable())
                    {
                        sendThread->join();
                    }

                    {
                        std::lock_guard<std::mutex> lock(mutexSocket);
                        if (!socket.is_open())
                        {
                            return;
                        }
                    }
                    asio::error_code ec;
                    socket.shutdown(asio::ip::tcp::socket::shutdown_receive);
                    socket.close(ec);
                    handler->onConnectionClosed(this->shared_from_this());
                }

                //注册编码器
                void registerEncoderHandler(std::string msgType, std::function<void(std::shared_ptr<rs::Any>, rs::buffer::ByteBuffer* sendBuffer)> encodeHandler)
                {
                    encodes.RegisterHandler(msgType, encodeHandler);
                }
                //注册解码器
                void registerDecoderHandle(std::string msgType, std::function<Any(rs::buffer::ByteBuffer* recevieBuffer)> decodeHandler)
                {
                    decodes.RegisterHandler(msgType, decodeHandler);
                }
                void registerLengthHandler(std::function<std::string(rs::buffer::ByteBuffer* recevieBuffer, int*)> f)
                {
                    decodes.RegisterHandler("length", f);
                }
                void registerSpi(std::shared_ptr<TcpClientI> client)
                {
                    handler = client;
                }
                void asyncSend(std::string msgType, Any msg)
                {
                    Msg msg1 = { msgType,msg };
                    if(sendMsgQueue.size_approx()>1000)
                    {
                        Msg msg;
                        sendMsgQueue.try_dequeue(msg);
                    }
                    sendMsgQueue.enqueue(msg1);
                }
                void send(std::string msgType, Any msg)
                {
                    if (status == TcpClientStatusConnected)
                    {
                        std::shared_ptr<Any>  msgPtr = std::make_shared<Any>(msg);
                        encodes.call_void(msgType, msgPtr, &sendBuffer);
                        startSendTx();
                    }
                    else
                    {
                        handler->onWarn("nosend" + msgType);
                    }
                }
                const asio::ip::tcp::socket& getSocket()
                {
                    return socket;
                }
                const TcpConfAsio getConfig()
                {
                    return tcpConfig;
                }
            private:
                void doReconnect()
                {
                    if ( status != CLOSED)
                    {
                        std::lock_guard<std::mutex> lock(mutexSocket);
                        if (!socket.is_open())
                        {
                            return;
                        }
                        asio::error_code ec;
                        socket.shutdown(asio::ip::tcp::socket::shutdown_receive);
                        socket.close(ec);
                        status = CONNECTING;
                        handler->onConnectionClosed(this->shared_from_this());
                        socket.async_connect(endpoint, connectHandle);
                    }

                }
                void doConnect()
                {
                    if (status!=CLOSED) {
                        status = CONNECTING;
                        sendBuffer.clear();
                        sending.store(false);
                        handler->onWarn("async connect 1");
                        socket.async_connect(endpoint, connectHandle);
                        handler->onWarn("async connect 1");
                    }
                }

                void StartReceive()
                {
                    {
                        //接收锁
                        if (receiving.load())
                        {
                            return;
                        }
                        receiving.store(true);
                    }
                    doRead();
                }
                void StartHeartBeat()
                {

                    timer.expires_from_now(std::chrono::seconds(tcpConfig.heartBeat));
                    timer.async_wait(std::bind(&TcpClientImpl::onHeartBeat, this->shared_from_this(), std::placeholders::_1));
                }
                void onHeartBeat(const asio::error_code& error)
                {
                    if (!error)
                    {
                        if (status == TcpClientStatusConnected)
                        {
                            if (!sending.load())
                            {

                                asyncSend("heartbeat", std::string("hello"));
                            }
                            startSendTx();
                            StartHeartBeat();
                        }
                    }
                }
                void doRead()
                {
                    socket.async_read_some(asio::buffer(receiveBuffer.dataWriting(), receiveBuffer.writableBytes()),readHandle);
                }


                void startSendTx()
                {
                    {
                        //send lock
                        if (sending.load())
                        {
                            handler->onWarn("sending ..." + status);
                            return;
                        }
                        if (sendBuffer.isReadable())
                        {
                            sending.store(true);
                        }
                        else
                        {
                            return;
                        }
                    }
                    sendTx();
                }
                void sendTx()
                {
                    socket.async_write_some(asio::buffer(sendBuffer.dataReading(),sendBuffer.readableBytes()),sendHandle);
                }

            private:
                void worker()
                {
                    try
                    {
                        ioContext.run();
                    }
                    catch (...)
                    {
                        int x = 0;
                        x++;
                    }
                    int i = 0;
                    i++;
                }
                void sendWork()
                {
                    while (inited)
                    {

                        if (sendBuffer.writableBytes() > MAX_MSG_SIZE)
                        {
                            Msg msg;
                            if (sendMsgQueue.wait_dequeue_timed(msg, std::chrono::microseconds(50)))
                            {
                                send(msg.msgType, msg.msg);
                            }
                        }
                        else
                        {
                            sendBuffer.discardReadBytes();
                            if (sendBuffer.writableBytes() <= MAX_MSG_SIZE)
                            {
                                std::this_thread::sleep_for(std::chrono::microseconds(100));
                            }
                        }

                    }
                }
            protected:
                std::function<void(asio::error_code)> connectHandle;
                std::function<void(asio::error_code, size_t)>  sendHandle;
                std::function<void(asio::error_code, size_t)>  readHandle;
            private:
                /**
                 * 底层上下文
                 */
                asio::io_context ioContext;
                std::thread* ioThread;
                asio::ip::tcp::endpoint endpoint;
                std::mutex mutexSocket;
                asio::ip::tcp::socket socket;

                std::atomic_bool sending;
                std::atomic_bool receiving;
                std::shared_ptr<TcpClientI> handler;
                //心跳使用
                asio::steady_timer timer;

                TcpConfAsio tcpConfig;
                /**
                 * 一个线程,无需加锁
                 */
                buffer::ByteBuffer sendBuffer;
                /**
                 * 一个线程,无需加锁
                 */
                buffer::ByteBuffer receiveBuffer;
                /**
                 * socket 状态
                 */
                volatile  TcpClientStatus status;

                msgbus::message_bus encodes;//编码msgbuss
                msgbus::message_bus decodes;//解码msgbuss

                std::thread* sendThread;

                volatile bool inited;
                /**
                 * 发送队列-定时器进行数据读取->Buffer
                 */
                moodycamel::BlockingConcurrentQueue<Msg> sendMsgQueue;
            };
            class TcpClientI
            {
            public:
                //right
                virtual void onConnected(std::shared_ptr<TcpClientImpl<>> client) = 0;
                //right
                virtual void onConnectionFailure(std::shared_ptr<TcpClientImpl<>> client, const asio::error_code& ec) = 0;
                virtual void onWarn(std::string) = 0;
                virtual void onSendError(std::shared_ptr<TcpClientImpl<>> client, const  asio::error_code& ec) = 0;
                virtual void onSendComplete(std::shared_ptr<TcpClientImpl<>> client, uint8_t*, size_t) = 0;
                virtual void onReceiveError(std::shared_ptr<TcpClientImpl<>> client, const asio::error_code& ec) = 0;
                virtual void onReceiveMsg(std::shared_ptr<TcpClientImpl<>> client, std::string msgType, Any& msg) = 0;
                virtual void onConnectionClosed(std::shared_ptr<TcpClientImpl<>> client) = 0;
            };
        }
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
		static inline uint64_t getTimeStamp() {
			auto nowTimePoint = std::chrono::system_clock::now();
			return std::chrono::duration_cast<std::chrono::milliseconds>(nowTimePoint.time_since_epoch()).count();
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
		 * 正则表达式验证
		 */
		inline  bool checkCornFormat(std::string const& cronStr)
		{
			cron_expr cornTmp;
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
	 * 定时任务，mutimap容器存放
	 */
	namespace schedules
	{
		class ScheduleTask
		{
		public:
			~ScheduleTask()
			{
				Stop();
			}
			bool RegistSchedule(std::string corn, std::function<void()> function)
			{
				if (quart::checkCornFormat(corn))
				{
					auto findMaps = functionMaps.find(corn);
					if (findMaps != functionMaps.end())
					{
						findMaps->second.push_back(function);
					}
					else
					{
						std::vector<std::function<void()>> v = { function };
						functionMaps[corn] = std::move(v);
					}
				}
				else
				{
					return false;
				}
			}

			void Run()
			{
				for (auto functionVector : functionMaps)
				{
					if (timesMap.find(functionVector.first) == timesMap.end())
					{
						timesMap[functionVector.first] = std::make_shared<asio::steady_timer>(ioContext);
					}
				}

				for (auto& timer_ : timesMap)
				{
					std::chrono::system_clock::time_point tp;
					quart::getNextTimePoint(timer_.first, tp);
					std::cout << StringUtils::TimeToString(std::chrono::system_clock::to_time_t(tp)) << std::endl;
					auto dur = tp - std::chrono::system_clock::now();
					timer_.second->expires_from_now(dur);
					timer_.second->async_wait(std::bind(&ScheduleTask::async_work, this, timer_.first, std::placeholders::_1));
				}
				scheduleThread = std::move(std::thread([&]()
				{
					ioContext.run();
				}));
			}
			void Stop()
			{
				for (auto& t : timesMap)
				{
					t.second->cancel();
				}
				if (!ioContext.stopped())
				{
					ioContext.stop();
				}
				if (scheduleThread.joinable())
				{
					scheduleThread.join();
				}
			}
		private:
			void async_work(std::string corn, std::error_code ec)
			{
				if (ec)
				{
					return;
				}
				{
					auto& dataIter = functionMaps.find(corn);
					if (dataIter != functionMaps.end())
					{
						for (auto& func : dataIter->second)
						{
							func();
						}
					}
				}
				try
				{
					auto& timer = timesMap[corn];
					std::chrono::system_clock::time_point tp;
					quart::getNextTimePoint(corn, tp);
					auto dur = tp - std::chrono::system_clock::now();
					timer->expires_from_now(dur);
					timer->async_wait(std::bind(&ScheduleTask::async_work, this, corn, std::placeholders::_1));

				}
				catch (...)
				{

				}
			};
		private:
			std::thread scheduleThread;
			std::map<std::string, std::shared_ptr<asio::steady_timer>> timesMap;
			asio::io_context ioContext;
			std::map<std::string, std::vector< std::function<void()>>> functionMaps;
		};
	};
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
	namespace zipkin
	{
		
		struct Annotation
		{
			uint64_t timestramp;
			std::string value;
		};
		struct Endpoint
		{
			std::string serviceName;
			std::string ipv4;
			uint16_t  port;
		};
		struct Span
		{
			std::string traceId;
			std::string name;
			std::string id;
			std::string parentId;
			uint64_t timestamp;
			uint64_t duration;
			Endpoint localEndpoint;
			std::vector<Annotation> annotations;
		};
		
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
#ifdef _WIN32
	namespace dumpbin
	{
		int GenerateMiniDump(PEXCEPTION_POINTERS pExceptionPointers);

		LONG WINAPI ExceptionFilter(LPEXCEPTION_POINTERS lpExceptionInfo);

	}
#endif
}

#endif /* RSUTILS */