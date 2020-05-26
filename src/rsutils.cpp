#include "rsutils.h"


void rs::uuid::Snowflake::setEpoch(uint64_t epoch)
{
	this->epoch = epoch;
}

void rs::uuid::Snowflake::setMachine(int machine)
{
	this->machine = machine;
}

uint64_t rs::uuid::Snowflake::generate()
{
	uint64_t value = 0;
	uint64_t time = getTime() - this->epoch;
	//时间41位
	value |= time << 21;
	//机器码10位
	value |= (this->machine & 0x3FF) << 13;
	//增量值12位
	value |= this->sequence++ & 0x1FFF;
	if (this->sequence == 0x10000) {
		this->sequence = 0;
	}
	return value;
}

uint64_t rs::uuid::Snowflake::getTime()
{
	FILETIME ft;
	uint64_t time = 0;
	static int tzflag;

	GetSystemTimeAsFileTime(&ft);

	time |= ft.dwHighDateTime;
	time <<= 32;
	time |= ft.dwLowDateTime;

	time /= 10;

	time -= 11644473600000000Ui64;

	return time / 1000;
}

std::once_flag rs::log::onceFlag;
static rs::log::LogType logType;
static const char* const levels[] = { "trace", "debug", "info", "warn", "error", "critical", "off" };

void rs::log::to_json(nlohmann::json& j, const DayLogConfig& obj)
{
	std::string fileLevel = "";
	std::string cmdLevel = "";
	cmdLevel = levels[obj.cmdLevel];
	fileLevel = levels[obj.fileLevel];
	if (fileLevel == "" || cmdLevel == "")
	{
		throw std::exception("DayLogConfig level is error");
	}
	j = nlohmann::json{ {"logName",obj.logName},{"hour",obj.hour},{"min",obj.min},{"fileLevel",fileLevel},{"cmdLevel",cmdLevel} };
}

void rs::log::from_json(const nlohmann::json& j, DayLogConfig& obj)
{
	j.at("logName").get_to(obj.logName);
	j.at("hour").get_to(obj.hour);
	j.at("min").get_to(obj.min);
	auto resultfileLevel = j.at("fileLevel").get<std::string>();
	auto resultcmdLevel = j.at("cmdLevel").get<std::string>();
	for (int i = 0; i < 7; ++i)
	{
		if (strcmp(levels[i], resultcmdLevel.c_str()) == 0)
		{
			obj.cmdLevel = spdlog::level::level_enum(i);
		}
		if (strcmp(levels[i], resultfileLevel.c_str()) == 0)
		{
			obj.fileLevel = spdlog::level::level_enum(i);
		}

	}
}

void rs::log::to_json(nlohmann::json& j, const RotatingLogConfig& obj)
{
	std::string fileLevel = levels[obj.fileLevel];
	std::string cmdLevel = levels[obj.cmdLevel];



	if (fileLevel == "" || cmdLevel == "")
	{
		throw std::exception("DayLogConfig level is error");
	}
	j = nlohmann::json{ {"logName",obj.logName},{"maxSize",obj.maxSize},{"fileNum",obj.fileNum},{"fileLevel",fileLevel},{"cmdLevel",cmdLevel} };
}

void rs::log::from_json(const nlohmann::json& j, RotatingLogConfig& obj)
{
	j.at("logName").get_to(obj.logName);
	j.at("maxSize").get_to(obj.maxSize);
	j.at("fileNum").get_to(obj.fileNum);
	auto resultfileLevel = j.at("fileLevel").get<std::string>();
	auto resultcmdLevel = j.at("cmdLevel").get<std::string>();
	for (int i = 0; i < 7; ++i)
	{
		if (levels[i] == resultcmdLevel.c_str())
		{
			obj.cmdLevel = spdlog::level::level_enum(i);
		}
		if (levels[i] == resultfileLevel.c_str())
		{
			obj.fileLevel = spdlog::level::level_enum(i);
		}

	}
}

rs::log::LoggerFactory::LoggerFactory()
{
	spdlog::init_thread_pool(4096, 1);
	spdlog::flush_every(std::chrono::seconds(1));
	initDay();
}

rs::log::LoggerFactory& rs::log::LoggerFactory::getInstance()
{
	return rs::design::singleton<LoggerFactory>::instance();
}

void rs::log::LoggerFactory::init(spdlog::level::level_enum cmdLevel)
{
	logType = LOGCMD;
	spdlog::init_thread_pool(4096, 1);
	auto cmdLogger = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
	cmdLogger->set_level(cmdLevel);
	sinks.push_back(cmdLogger);
}

void rs::log::LoggerFactory::initDay()
{
	JsonUtils::FileToClass(StringUtils::getAppPathRS() + "config" + StringUtils::PathSeparatorRS() + "log.json", d);
	sinks.clear();
	init(d.cmdLevel);
	logType = LOGDAY;
	auto strPath = StringUtils::getAppPathRS() + "ServerLog";
	StringUtils::CreateFolderRS(strPath);
	std::string logFilesp = strPath + StringUtils::PathSeparatorRS() + d.logName;
	try {
		auto dayFileLogger = std::make_shared<spdlog::sinks::daily_file_sink_mt>(logFilesp, d.hour, d.min);
		dayFileLogger->set_level(d.fileLevel);
		sinks.push_back(dayFileLogger);
	}
	catch (const std::exception& e) {
		std::cout << "sinks push error:" << e.what() << std::endl;
		std::this_thread::sleep_for(std::chrono::seconds(5));
		exit(1);
	}
}

void rs::log::LoggerFactory::initRotate()
{
	sinks.clear();
	JsonUtils::FileToClass(StringUtils::getAppPathRS() + "config" + StringUtils::PathSeparatorRS() + "log.json", config);
	init(config.cmdLevel);
	logType = LOGROTATI;
	auto strPath = StringUtils::getAppPathRS() + "ServerLog";
	StringUtils::CreateFolderRS(strPath);
	try {
		auto 	rotatFileLogger = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(strPath + StringUtils::PathSeparatorRS() + config.logName, config.maxSize * 1024 * 1024, config.fileNum);
		rotatFileLogger->set_level(config.fileLevel);
		sinks.push_back(rotatFileLogger);
	}
	catch (const std::exception& e) {
		std::cout << "sinks push error:" << e.what() << std::endl;
		std::this_thread::sleep_for(std::chrono::seconds(5));
		exit(1);
	}
}

rs::log::LoggerFactory::~LoggerFactory()
{
	spdlog::drop_all();
}

void rs::log::LoggerFactory::updateLogConfig(spdlog::level::level_enum cmdLevel, spdlog::level::level_enum fileLevel)
{
	std::string configPath = StringUtils::getAppPathRS() + "config";
	switch (logType)
	{
	case LOGDAY:

		if (!JsonUtils::FileToClass(configPath + StringUtils::PathSeparatorRS() + "log.json", d))
		{
			StringUtils::CreateFolderRS(configPath);
		}

		d.cmdLevel = cmdLevel;
		d.fileLevel = fileLevel;
		sinks[0]->set_level(cmdLevel);
		sinks[1]->set_level(fileLevel);
		JsonUtils::ClassToFile(configPath + StringUtils::PathSeparatorRS() + "log.json", d);
		break;
	case LOGROTATI:
		if (!JsonUtils::FileToClass(configPath + StringUtils::PathSeparatorRS() + "log.json", config))
		{
			StringUtils::CreateFolderRS(configPath);
		}
		config.cmdLevel = cmdLevel;
		config.fileLevel = fileLevel;

		sinks[0]->set_level(cmdLevel);
		sinks[1]->set_level(fileLevel);
		JsonUtils::ClassToFile(configPath + StringUtils::PathSeparatorRS() + "log.json", config);
		break;
	case LOGCMD:
		sinks[0]->set_level(cmdLevel);
		break;
	default:
		break;
	}
}

rs::log::LOGGER rs::log::LoggerFactory::getLogger(const char* loggername)
{
	auto logTmp = spdlog::get(loggername);
	if (logTmp != nullptr) {
		return logTmp;
	}

	auto logger = std::make_shared<spdlog::async_logger>(loggername, sinks.begin(), sinks.end(), spdlog::thread_pool(), spdlog::async_overflow_policy::block);

	logger->set_level(spdlog::level::trace);//取该级别与具体sinks的交集
	spdlog::register_logger(logger);
	//spdlog::set_pattern("[%Y-%m-%dT%T.%FZ] [Pid:%P] [thread %t] [%n] [%l] %v%$");
	//spdlog::set_pattern("[%Y-%m-%dT%T.%FZ] [thread %t] [%n] [%l] %v%$");
	//spdlog::set_pattern("[%Y-%m-%dT%T.%FZ][Pid:%P] [thread %t] [%n] [%l] %v%$");
	return logger;
}

int64_t rs::clock::TimerClock::elapsed() const
{
	return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - m_begin).count();
}

int64_t rs::clock::TimerClock::elapsed_second() const
{
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::high_resolution_clock::now() - m_begin).count();
}

int64_t rs::clock::TimerClock::elapsed_micro() const
{
	return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - m_begin).count();
}

int64_t rs::clock::TimerClock::elapsed_nano() const
{
	return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now() - m_begin).count();
}

int64_t rs::clock::TimerClock::elapsed_minutes() const
{
	return std::chrono::duration_cast<std::chrono::minutes>(std::chrono::high_resolution_clock::now() - m_begin).count();
}

int64_t rs::clock::TimerClock::elapsed_hours() const
{
	return std::chrono::duration_cast<std::chrono::hours>(std::chrono::high_resolution_clock::now() - m_begin).count();
}

std::shared_ptr<rs::clock::TimerClock> rs::clock::TimerClockFactory::getInstance()
{
	return std::make_shared<TimerClock>();
}

rs::buffer::ByteBuffer::ByteBuffer(uint32_t size)
{
	buf = new uint8_t[size];
	capacity_ = size;
	clear();
}

rs::buffer::ByteBuffer::~ByteBuffer()
{
	delete buf;
}

uint32_t rs::buffer::ByteBuffer::capacity()
{
	return capacity_;
}

void rs::buffer::ByteBuffer::clear()
{
	readerIndex_ = 0;
	writerIndex_ = 0;
	memset(buf, 0, capacity_);
}

rs::buffer::ByteBuffer* rs::buffer::ByteBuffer::discardReadBytes()
{
	if (readerIndex_ == 0) {
		return this;
	}
	if (readerIndex_ != writerIndex_) {
		memcpy(buf, &buf[readerIndex_], writerIndex_ - readerIndex_);
		writerIndex_ -= readerIndex_;
		adjustMarkers(readerIndex_);
		readerIndex_ = 0;
	}
	else {
		adjustMarkers(readerIndex_);
		writerIndex_ = readerIndex_ = 0;
	}
	return this;
}

uint32_t rs::buffer::ByteBuffer::readerIndex()
{
	return readerIndex_;
}

void rs::buffer::ByteBuffer::readerIndex(uint32_t readerIndex) const
{
	readerIndex_ = readerIndex;
}

uint32_t rs::buffer::ByteBuffer::writerIndex()
{
	return writerIndex_;
}

void rs::buffer::ByteBuffer::writerIndex(uint32_t writerIndex)
{
	writerIndex_ = writerIndex;
}

bool rs::buffer::ByteBuffer::setIndex(int readerIndex__, int writerIndex__)
{
	if (checkIndexBounds(readerIndex__, writerIndex__, capacity_)) {
		readerIndex(readerIndex__);
		writerIndex(writerIndex__);
	}
	else {
		return false;
	}
}

uint32_t rs::buffer::ByteBuffer::readableBytes()
{
	return writerIndex_ - readerIndex_;
}

uint32_t rs::buffer::ByteBuffer::writableBytes()
{
	return capacity_ - writerIndex_;
}

bool rs::buffer::ByteBuffer::isReadable()
{
	return writerIndex_ > readerIndex_;
}

bool rs::buffer::ByteBuffer::isReadable(int numBytes)
{
	return writerIndex_ - readerIndex_ > numBytes;
}

bool rs::buffer::ByteBuffer::isWritable()
{
	return capacity_ > writerIndex_;
}

bool rs::buffer::ByteBuffer::isWritable(int numBytes)
{
	return capacity_ - writerIndex_ > numBytes;
}

rs::buffer::ByteBuffer* rs::buffer::ByteBuffer::markReaderIndex()
{
	markReaderIndex_ = readerIndex_;
	return this;
}

rs::buffer::ByteBuffer* rs::buffer::ByteBuffer::resetReaderIndex()
{
	readerIndex(markReaderIndex_);
	return this;
}

rs::buffer::ByteBuffer* rs::buffer::ByteBuffer::markWriterIndex()
{
	markWriterIndex_ = writerIndex_;
	return this;
}

rs::buffer::ByteBuffer* rs::buffer::ByteBuffer::resetWriterIndex()
{
	writerIndex(markWriterIndex_);
	return this;
}

uint8_t* rs::buffer::ByteBuffer::data()
{
	return buf;
}

uint8_t* rs::buffer::ByteBuffer::dataReading()
{
	return &buf[readerIndex_];
}

uint8_t* rs::buffer::ByteBuffer::dataWriting()
{
	return &buf[writerIndex_];
}

bool rs::buffer::ByteBuffer::skip(size_t skipStep)
{
	if (skipStep <= readableBytes()) {
		readerIndex(readerIndex_ + skipStep);
		return false;
	}
	else {
		return false;
	}
}

bool rs::buffer::ByteBuffer::writeSkip(size_t skipStep)
{
	writerIndex(writerIndex_ + skipStep);
	return true;
}

rs::buffer::ByteBuffer* rs::buffer::ByteBuffer::capacity(int newCapacity)
{
	uint8_t* tmp = new uint8_t[newCapacity];
	if (readableBytes() > 0) {
		memcpy(tmp, &buf[readerIndex_], readableBytes());
	}
	delete buf;
	buf = tmp;
	markWriterIndex_ = writerIndex_ = readableBytes();
	markReaderIndex_ = readerIndex_ = 0;
	capacity_ = newCapacity;
	return this;
}

int rs::dumpbin::GenerateMiniDump(PEXCEPTION_POINTERS pExceptionPointers)
{
	// 定义函数指针
	typedef BOOL(WINAPI * MiniDumpWriteDumpT)(
		HANDLE,
		DWORD,
		HANDLE,
		MINIDUMP_TYPE,
		PMINIDUMP_EXCEPTION_INFORMATION,
		PMINIDUMP_USER_STREAM_INFORMATION,
		PMINIDUMP_CALLBACK_INFORMATION
		);
	// 从 "DbgHelp.dll" 库中获取 "MiniDumpWriteDump" 函数
	MiniDumpWriteDumpT pfnMiniDumpWriteDump = NULL;
	HMODULE hDbgHelp = LoadLibrary(_T("DbgHelp.dll"));
	if (NULL == hDbgHelp)
	{
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	pfnMiniDumpWriteDump = (MiniDumpWriteDumpT)GetProcAddress(hDbgHelp, "MiniDumpWriteDump");

	if (NULL == pfnMiniDumpWriteDump)
	{
		FreeLibrary(hDbgHelp);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	// 创建 dmp 文件件
	TCHAR szFileName[MAX_PATH] = { 0 };
	TCHAR* szVersion = _T("DumpDemo_v1.0");
	SYSTEMTIME stLocalTime;
	GetLocalTime(&stLocalTime);
	wsprintf(szFileName, "%s-%04d%02d%02d-%02d%02d%02d.dmp",
		szVersion, stLocalTime.wYear, stLocalTime.wMonth, stLocalTime.wDay,
		stLocalTime.wHour, stLocalTime.wMinute, stLocalTime.wSecond);
	HANDLE hDumpFile = CreateFile(szFileName, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_WRITE | FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);
	if (INVALID_HANDLE_VALUE == hDumpFile)
	{
		FreeLibrary(hDbgHelp);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	// 写入 dmp 文件
	MINIDUMP_EXCEPTION_INFORMATION expParam;
	expParam.ThreadId = GetCurrentThreadId();
	expParam.ExceptionPointers = pExceptionPointers;
	expParam.ClientPointers = FALSE;
	pfnMiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(),
		hDumpFile, MiniDumpWithFullMemory, (pExceptionPointers ? &expParam : NULL), NULL, NULL);
	// 释放文件  MiniDumpWithDataSegs  MiniDumpNormal
	CloseHandle(hDumpFile);
	FreeLibrary(hDbgHelp);
	return EXCEPTION_EXECUTE_HANDLER;
}

LONG __stdcall rs::dumpbin::ExceptionFilter(LPEXCEPTION_POINTERS lpExceptionInfo)
{
	// 这里做一些异常的过滤或提示
	if (IsDebuggerPresent())
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}
	return GenerateMiniDump(lpExceptionInfo);
}
std::shared_ptr<rs::web::WebServer> rs::web::webServer;
std::once_flag rs::web::onceFlagWeb;
rs::web::WebServer::WebServer()
{
	Start();
}

rs::web::WebServer::~WebServer()
{
	Stop();
}

void rs::web::WebServer::Start()
{
	Init();
	if (!JsonUtils::FileToClass(StringUtils::getAppPathRS() + "config" + StringUtils::PathSeparatorRS() + "web.json", webConf))
	{
		webConf.ip = "127.0.0.1";
		webConf.port = 80;
		webConf.path = "web";
	}
	web.set_base_dir((StringUtils::getAppPathRS() + webConf.path).data());
	std::thread t([&]()
	{
		loggerWeb->info("web listening {}:{}", webConf.ip, webConf.port);
		web.listen(webConf.ip.c_str(), webConf.port);
	});
	t.detach();
}

void rs::web::WebServer::Stop()
{
	loggerWeb->info("stop");
	web.stop();
	std::this_thread::sleep_for(std::chrono::seconds(2));
}

void rs::web::WebServer::Init()
{
	web.Options(R"(\*)", CrosDomain);
	web.Get("/config/web", [&](const httplib::Request& req, httplib::Response& res)
	{
		//CrosDomain(req, res);
		std::string result = "server closeed";
		rs::JsonUtils::ClassToString(result, webConf);
		res.set_content(result, "application/json");
	});
	web.set_error_handler([](const httplib::Request& /*req*/, httplib::Response& res) {
		const char* fmt = "<p>Error Status: <span style='color:red;'>%d</span></p>";
		char buf[BUFSIZ];
		snprintf(buf, sizeof(buf), fmt, res.status);
		res.set_content(buf, "text/html");
	});
	loggerWeb->info("init success");
}

void rs::web::callOnceInstanceWeb()
{
	webServer = std::make_shared<WebServer>();
}
static std::shared_ptr<rs::zabbix::ZbxSender> zbx;
static std::once_flag onceFlagZabbix;

rs::zabbix::ZbxSender::ZbxSender()
{
	// Create a daily logger - a new file is created every day on 2:30am
	std::string  logdir = StringUtils::getAppPathRS() + "zabbix" + StringUtils::PathSeparatorRS() + "logs";
	StringUtils::CreateFolderRS(logdir);

	//logger = spdlog::daily_logger_mt("daily_logger", logdir+"\\zabbix.log", 2, 30);
	logger = spdlog::daily_logger_st("daily_logger", logdir + "\\zabbix.log", 2, 30);
	spdlog::flush_every(std::chrono::seconds(1));
	auto resFileToclass = JsonUtils::FileToClass(StringUtils::getAppPathRS() + "zabbix/zabbix.json", config);
	if (!resFileToclass) {
		logger->info("zabbix config not find or error");
	}
	ready = true;
	std::thread worker(&ZbxSender::run, this);
	worker.detach();
}

void rs::zabbix::ZbxSender::send(std::string data)
{
	queue.push(data);
}

rs::zabbix::ZbxSender::~ZbxSender()
{
	ready = false;
}

void rs::zabbix::ZbxSender::run()
{
	logger->info("zabbixSender started");
	while (ready)
	{
		if (!queue.empty())
		{
			std::string data = queue.front();
			queue.pop();
			tcp_send(data);
		}

		if (queue.size() > 100)
		{
			queue.empty();
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
}

bool rs::zabbix::ZbxSender::tcp_send(std::string value)
{
	asio::io_service io_service;
	asio::ip::tcp::socket socket(io_service);
	try
	{
		socket.connect(asio::ip::tcp::endpoint(asio::ip::address::from_string(config.ZabbixHost),
			config.ZabbixPort));
	}
	catch (std::exception& e)
	{
		logger->warn("{}: datadetail:{}", e.what(), value);
		return false;
	}

	if (value.length() > 4000)
	{
		logger->error("msg is too long:{}", value);
		return false;
	}

	char msg[4096];
	memset(msg, 0x00, 4096);
	//strcpy_s(msg, "ZBXD");
	strcpy(msg, "ZBXD");
	//strcpy(msg, "ZBXD");
	msg[4] = 0x01;
	zabbixData data;
	zabbixCoreData coredata;
	coredata.host = config.MonitoringHost;
	coredata.key = config.MonitoringKey;
	coredata.value = value;
	data.data.push_back(coredata);
	std::string DATA;
	JsonUtils::ClassToString(DATA, data);
	int32_t data_len = DATA.length();
	memcpy(msg + 5, &data_len, sizeof(int32_t));
	memcpy(msg + 13, DATA.c_str(), DATA.length());

	asio::error_code error;
	asio::write(socket, asio::buffer(msg, data_len + 13), error);

	if (error)
	{
		TextError = "send failed: " + error.message();
		logger->error("{} data detail:{}", TextError, DATA);
	}
	else
	{
		logger->info("send:{}", value);
	}

	asio::streambuf receive_buffer;
	asio::read(socket, receive_buffer, asio::transfer_all(), error);

	if (error && error != asio::error::eof)
	{
		logger->error("receive failed: {}", error.message());
	}
	else
	{
		const char* data = asio::buffer_cast<const char*>(receive_buffer.data());
		logger->info("receive data:{}", data);
	}

	return 0;
}

void rs::zabbix::newInstanceCallOnce()
{
	zbx = std::make_shared<ZbxSender>();
}

void rs::zabbix::send(std::string msg)
{
	if (zbx)
	{
		zbx->send(msg);
	}
	else
	{
		std::call_once(onceFlagZabbix, newInstanceCallOnce);
		zbx->send(msg);
	}
}
