# 工具类包
## 依赖
asio  
nlohmann::json  
spdlog  
sqlite_modern_cpp  
ccronexpr  
concurrentqueue  
httplib  
ThreadPool 
## 使用方法
### 雪花片UUID生成工具
TODO:
###  String工具类  
```
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
```
### clock性能测试  
使用方法栈上使用
```
    using namespace rs::clock;
    auto timerClockPtr = TimerClockFactory::getInstance();
    std::this_thread::sleep_for(std::chrono::seconds(3));
    std::cout << timerClockPtr->elapsed_second() << std::endl;
    timerClockPtr->reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(3));
    auto reult = timerClockPtr->elapsed();
    std::cout << reult << std::endl;
```
### ByteBuffer
字节数组  
TODO:  
### cron支持
```
    using namespace rs::quart;
    std::string cron = "0 0 10 * * *";
    std::chrono::system_clock::time_point ti;
    if (getNextTimePoint(cron, ti))
    {
    	auto tim = std::chrono::system_clock::to_time_t(ti);
    	auto reString = rs::StringUtils::TimeToString(tim);
    	std::cout << reString << std::endl;
    }
```
### web支持
采用约定大于配置的方式,默认开放80端口,如果不进行绑定,则不会使用该框架,也不会有额外线程消耗
```
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
```
### log支持
使用前需要注意修改rs::log中的getLogger初始化中的callOnce,指定采用的是哪种log方式.如果不进行任何修改,默认使用控制台日志.
目前有3中,1 only cmd 2 daylog+cmd 3 rotating+cmd
其中2,3 会找config目录下的log.json配置  
daylog配置
```
{
"logName":"system.log",
"hour":1,
"min":1,
"fileLevel":"debug",
"cmdLevel":"info"
}
```
rotating配置 
```
{
"logName":"system.log",
"fileNum":3,
"maxSize":100,
"fileLevel":"debug",
"cmdLevel":"info"
}
```
```
using namespace rs::log;
static auto mainLog = rs::log::getLogger("main");
mainLog->info("cmd log :{}", 23);
```
### dumpbin
仅限于win平台
```
int main(int argc, char* argv[])
{
	SetUnhandledExceptionFilter(rs::dumpbin::ExceptionFilter);
}
```
### zabbix支持
需要默认配置项
在zabbix目录下,创建zabbix.json
```
{
  "ZabbixHost": "192.168.1.2",
  "ZabbixPort": 10051,
  "MonitoringHost": "192.168.1.159",
  "MonitoringKey": "sgxMarket"
}
```
使用方法:
zabbix单独占用一个线程,因此如果程序过早退出,那么会发生发不出去的情况,采用懒加载的方式,不需要担心不使用该组件会创建该对象
```
	rs::zabbix::send("asdf");
	std::this_thread::sleep_for(std::chrono::seconds(3));
```