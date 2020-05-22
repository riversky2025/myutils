# CMakeList.txt: CMakeProject1 的 CMake 项目，在此处包括源代码并定义
# 项目特定的逻辑。
#
cmake_minimum_required (VERSION 3.8)
include_directories(.\\include )
aux_source_directory(.\\src  DIR_SRCS)
# 将源代码添加到此项目的可执行文件。
add_compile_definitions("CRON_USE_LOCAL_TIME")
add_executable (CMakeProject1 ${DIR_SRCS} )

# TODO: 如有需要，请添加测试并安装目标。

