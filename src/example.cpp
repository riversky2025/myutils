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
	std::string cron = "0 50 9 * * *";
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
void messageBusTest()
{
	rs::msgbus::message_bus ms;
	ms.RegisterHandler("a", [](int a, int b, int c)
	{
		return a + b + c;
	});
	ms.RegisterHandler("b", [](int c, int a) { std::cout << c << "  " << a << std::endl; });
	ms.call_void("b", 2, 3);
	auto re = ms.call<int>("a", 1, 2, 4);
	std::cout << re << std::endl;

}
class MyTcpHandler :public rs::socket::tcp::TcpClientI
{
public:
	//right
	virtual void onConnected(std::shared_ptr<rs::socket::tcp::TcpClientImpl<>> client) override
	{
		const auto& so = client->getSocket();

		mainLog->info("local connected success( {}:{})", so.local_endpoint().address().to_string(), so.local_endpoint().port());
	}
	//right
	virtual void onConnectionFailure(std::shared_ptr<rs::socket::tcp::TcpClientImpl<>> client, const asio::error_code& ec)
	{
		mainLog->info("disconnected ( {}:{})", client->getConfig().ip, client->getConfig().port);
	}

	virtual void onSendError(std::shared_ptr<rs::socket::tcp::TcpClientImpl<>> client, const  asio::error_code& ec)
	{
		mainLog->info("send error");
	}
	virtual void onSendComplete(std::shared_ptr<rs::socket::tcp::TcpClientImpl<>> client, uint8_t* msgPtr, size_t sizeMsg)
	{
		mainLog->info("send ok:{}", std::string((char*)msgPtr, sizeMsg));
	}
	virtual void onReceiveError(std::shared_ptr<rs::socket::tcp::TcpClientImpl<>> client, const asio::error_code& ec)
	{
		mainLog->info("receive error:{}", ec.message());
	}
	virtual void onReceiveMsg(std::shared_ptr<rs::socket::tcp::TcpClientImpl<>> client, std::string typeMsg, rs::Any& msg)
	{
		auto msgStr = msg.AnyCast<std::string>();
		mainLog->info("receive success type:{},msg:{}", typeMsg, msgStr);
		if (msgStr.find("stop") != std::string::npos)
		{
			client->Stop();
		}
	}
	virtual void onConnectionClosed(std::shared_ptr<rs::socket::tcp::TcpClientImpl<>> client)
	{
		mainLog->info("connect closed");
	}
};
void testTcp()
{
	rs::socket::tcp::TcpConfAsio config = { "192.168.1.159",10000,1,10,5 };
	auto target = std::make_shared<rs::socket::tcp::TcpClientImpl<>>(config);
	auto myHandler = std::make_shared<MyTcpHandler>();
	target->registerSpi(myHandler);
	target->registerEncoderHandler("heartbeat", [](std::shared_ptr<rs::Any> msg, rs::buffer::ByteBuffer* sendBuffer)
	{
		auto data = msg->AnyCast<std::string>();
		sendBuffer->putBytes(data.c_str());
	});
	target->registerEncoderHandler("bbb", [](std::shared_ptr<rs::Any>msg, rs::buffer::ByteBuffer* densBuffer)
	{
		auto data = msg->AnyCast<std::string>();
		densBuffer->putBytes(data.c_str());
	});
	target->registerLengthHandler([](rs::buffer::ByteBuffer* receive, int* length)->std::string
	{
		*length = receive->readableBytes();
		std::string e((char*)receive->dataReading(), 3);
		return e;
	});
	target->registerDecoderHandle("aaa", [](rs::buffer::ByteBuffer* receive)->rs::Any
	{
		std::string e((char*)receive->dataReading(), receive->readableBytes());
		return e;
	});
	target->Start();
	std::atomic_uint64_t  iSidat;
	std::thread a([&, target]()
	{
		while (true)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(5));
			auto msg = fmt::format("msg a({})", iSidat.fetch_add(1));
			mainLog->info("send:{}", msg);
			target->send("bbb", msg);
		}
	});
	a.join();

}


void testSchedule()
{
	auto& t = rs::design::singleton<rs::schedules::ScheduleTask>::instance();

	t.RegistSchedule("1 * * * * *", []() {	mainLog->info("bala1");	});
	t.RegistSchedule("32 * * * * *", []() {	mainLog->info("bala2");	});
	t.RegistSchedule("13 * * * * *", []() {	mainLog->info("bala3");	});


}
void testSchedulestep2()
{
	auto& t = rs::design::singleton<rs::schedules::ScheduleTask>::instance();
	t.RegistSchedule("21 * * * * *", []() {	mainLog->info("bala11");	});
	t.RegistSchedule("48 * * * * *", []() {	mainLog->info("bala18");	});
	t.RegistSchedule("59 * * * * *", []() {	mainLog->info("bala19");	});
	t.Run();
	std::this_thread::sleep_for(std::chrono::minutes(1));
	t.Stop();
}
int main(int argc, char* argv[])
{
	//testUUID();
	//testString();
	//testClock();
	//testCron();
	//testWeb();
	//testlog();
	//testZbx();
	//messageBusTest();

	//testTcp();
	testSchedule();
	testSchedulestep2();
	//system("pause");
	return 0;
}
