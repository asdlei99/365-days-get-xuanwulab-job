# AFL源码注释

## 0x01 debug.h

定义了各种开发调试用的宏. 

* 有终端控制字符(比如控制终端输出的颜色, 可视化绘画界面用的宏以及其他控制字符).
* 调试输出用的宏,  主要是`SAYF`宏, 然后衍生出WARNF, ACTF, OKF, BADF, FATAL, ABORT, PFATAL, RPFATAL用于日志分级输出. 另外定义了ck_write和ck_read, 在write和read基础上添加了check

## 0x02 hash.h

定义了一个*MurmurHash3*变种哈希算法, 有分32和64位分别实现. 主要追求效率而并非是一个安全的哈希算法, 并且也不支持非8倍数长度的buf进行哈希. 

## 0x03 types.h

* 定义了一些类型的别名, 比如u64, s8, s16, s32, s64. 
* 简单的算术操作, 比如MIN, MAX, SWAP16, SWAP32
* 随机数: 生成方法 random() % (x) 不过会因为是否处于LLVM模式而名称有点变化, 但其实没有什么影响. 
* STRINGIFY: 用于显示变量的名称, 比如STRINGIFY(x) 就是"x"这样
* MEM_BARRIER: 内存屏障, 避免指令重排
* likely和unlikely 用于分支预测优化

## 0x04 config.h

定义了afl的一些配置信息. TODO: 需要时补充

## 0x05 afl-fuzz.c

从main函数开始看起

### 1. 处理函数命令行参数

定义了`i:o:f:m:b:t:T:dnCB:S:M:x:QV`参数. 释义如下:

* i: input dir
* o: output dir
* M: master sync ID, 指定当前fuzzer作为主人, 不能跟-S选项同时使用
* S: slave sync ID, 指定当前fuzzer作为仆从, 不能跟-M选项同时使用
* f: target file, 对应变量out_file
* x: *dictionary*, 字典目录, 对应变量extras_dir
* t: timeout, 超时时间, 对应变量exec_tmout, 时间单位对应suffix
* m: 内存限制, 对应变量mem_limit, 时间可选单位有T, G, k, M
* b:  *bind CPU core*, 对应变量cpu_to_bind
* d: *skip deterministic*, 跳过确定性策略, 会将skip_deterministic和use_splicing置1
* B: *load bitmap*, 未文档化的一个选项, 对应变量in_bitmap, 当你在fuzz过程中找到一个有趣的测试用例时, 并且想要直接对其进行变异时使用.
* C: *crash mode*, 对应变量crash_mode设置为FAULT_CRASH
* n: dumb mode, 会根据是否存在AFL_DUMB_FORKSRV环境变量而将dumb_mode设置为2或1
* T: user banner
* Q: QEMU mode, 将qemu_mode置为1, 并且将内存限制默认设置为MEM_LIMIT_QEMU, 即200M
* V: version, 显示版本

### 2. 初始化配置以及相关检查

* setup_signal_handlers: 注册一些信号处理的函数
* check_asan_opts: 检查ASAN和MSAN的选项是否有冲突的地方
* fix_up_sync: 检验sync ID是否合法以及修正slave的out_dir和sync_dir
* 检查in_dir和out_dir是否重合, 检查是否存在dump_mode和crash_mode & qemu_mode冲突
* 读取环境变量, 对一些开关进行置位或者赋值: 
  * AFL_NO_FORKSRV
  * AFL_NO_CPU_RED
  * AFL_NO_ARITH
  * AFL_SHUFFLE_QUEUE
  * AFL_FAST_CAL
  * AFL_HANG_TMOUT
* 检查是否同时设置了AFL_DUMB_FORKSRV and AFL_NO_FORKSRV环境变量(冲突)
* 设置了AFL_PRELOAD情况下, 会设置相关的环境变量LD_PRELOAD, DYLD_INSERT_LIBRARIES并且不建议使用环境变量AFL_LD_PRELOAD
* 

