// CMakeProject1.cpp: 定义应用程序的入口点。
//

#include "rsutils.h"
#include <iostream>

void testUUID()
{
	auto logger = rs::log::getLogger("uuid");
	rs::uuid::Snowflake s;
	rs::uuid::Snowflake s1;
	s1.setEpoch(1);
	s1.setMachine(1);
	s.setEpoch(1);
	s.setMachine(2);
	for (int i = 0; i < 100; ++i)
	{
		logger->info("s1:{},s2:{}", s.generate(), s1.generate());
	}
}
/**
 * StringUtils测试
 */
void testString()
{
	using namespace rs;
	auto apppath = StringUtils::getAppPathRS();
	std::cout << apppath << std::endl;
	std::string a = "sgx@uc2012@12@Busf@f@@";
	auto aVec = StringUtils::Split(a, "@");
	auto bVec = StringUtils::Split(a, "@", true);
	std::cout << aVec.size() << std::endl;
	std::cout << bVec.size() << std::endl;
	std::cout << StringUtils::Join(aVec, "*") << std::endl;
	std::cout << StringUtils::PathSeparatorRS() << std::endl;
	auto timeA = StringUtils::convFromStr("2020-05-18T10:50:00");
	std::cout << timeA << std::endl;
	std::cout << StringUtils::ToUpper(a) << std::endl;
	std::cout << StringUtils::ToLower(a) << std::endl;
}
#include <thread>
void testClock()
{
	using namespace rs::clock;
	auto timerClockPtr = TimerClockFactory::getInstance();
	std::this_thread::sleep_for(std::chrono::seconds(3));
	std::cout << timerClockPtr->elapsed_second() << std::endl;
	timerClockPtr->reset();
	std::this_thread::sleep_for(std::chrono::milliseconds(3));
	auto reult = timerClockPtr->elapsed();
	std::cout << reult << std::endl;
}
void testCron()
{
	using namespace rs::quart;
	std::string cron = "0 0 10 * * *";
	std::chrono::system_clock::time_point ti;
	if (getNextTimePoint(cron, ti))
	{
		auto tim = std::chrono::system_clock::to_time_t(ti);
		auto reString = rs::StringUtils::TimeToString(tim);
		std::cout << reString << std::endl;
	}
}
void getDemo1(const httplib::Request& req, httplib::Response& resp)
{
	nlohmann::json f{ "msg",{"data","helloword"} };
	std::string result = f.dump();
	resp.set_content(result, "application/json");
}
void postDemo(const httplib::Request& req, httplib::Response& resp)
{
	auto reqBody = req.body;
	resp.set_content(reqBody, "application/json");
}
void testWeb()
{

	rs::web::Bind<true>("/api/getDemo", getDemo1);
	rs::web::Bind<false>("/api/postDemo", postDemo);

}

/**
 * 使用原则,类内log
 */
static auto mainLog = rs::log::getLogger("main");
void testlog()
{
	using namespace rs::log;
	//默认info
	for (int i = 0; i < 100; ++i)
	{
		mainLog->info("hello info");
		mainLog->debug("hello trance");
		mainLog->error("error");
		mainLog->trace("trance");
		//rs::log::LoggerFactory::getInstance().updateLogConfig(spdlog::level::trace, spdlog::level::debug);
		mainLog->info("hello info");
		mainLog->debug("hello trance");

		mainLog->info("cmd log :{}", 23);
	}
	//LoggerFactory::getInstance().updateLogConfig(spdlog::level::trace, spdlog::level::trace);
	system("pause");
	for (int i = 0; i < 100; ++i)
	{
		mainLog->info("hello info");
		mainLog->debug("hello trance");
		mainLog->error("error");
		mainLog->trace("trance");

		mainLog->info("hello info");
		mainLog->debug("hello trance");

		mainLog->info("cmd log :{}", 23);
	}


}
void testZbx()
{
	rs::zabbix::send("zabbix good");
	std::this_thread::sleep_for(std::chrono::seconds(3));
}


void spdlogTest()
{

}
int main(int argc, char* argv[])
{
	//testUUID();
	//testString();
	//testClock();
	//testCron();
	//testWeb();
	testlog();
	//testZbx();
	system("pause");
	return 0;
}
