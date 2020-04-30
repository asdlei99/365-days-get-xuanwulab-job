# 365天获取玄武实验室的工作

## 这是什么? 

这是一份我给自己365天内获取腾讯玄武实验室工作定下的学习进度清单, 用于记录我在这一年时间里每天的学习收获. 

因为知识积累的差异, 该清单并不适用于纯粹的新手, 但我常认为自己是一个愚笨的人, 所以即便是刚入行的小白, 在补足了一定的基础知识后, 该清单依然具有一定的参考价值. 

## 学习进度

<details>
<summary>Day1: 学习CTF Wiki栈溢出基础和ROP基础</summary>

> 传送门: [CTF Wiki: Linux Pwn](https://ctf-wiki.github.io/ctf-wiki/pwn/readme-zh/)

- [x] [Stack Overflow Principle](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/stackoverflow-basic-zh/): 通过栈溢出覆盖掉函数栈帧的返回地址, 当函数返回时就会跳入攻击者覆写的地址继续执行代码. 
    1. 确认溢出的长度可以到达栈帧返回地址
    2. 确认没有开启Stack Canary
    3. 确认覆写的地址所在的段具有执行权限
    * 编译选项`-fno-stack-protector`用于关闭Stack Canary
    * 编译时需要加`-no-pie`确保不会生成位置无关文件
    *  关闭ASLR: `echo 0 > /proc/sys/kernel/randomize_va_space`
- [x] [Basic ROP](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/basic-rop-zh/): 在栈溢出的基础上, 通过利用文件本身的gadget来控制寄存器和变量来控制程序流程.
    - [x] ret2text: 跳转到程序已有的高危代码处(`system("/bin/sh")`), 直接触发高危操作.
    - [x] ret2shellcode: 栈溢出的同时布置shellcode(可以理解为预写好的高危功能性汇编代码), 在溢出时跳转到布置好的shellcode处继续执行.
        1. 因为有执行, 所以需要确保shellcode所在位置有可执行权限.
        2. gef的`vmmap`可以查看内存段的权限.
        3. pwntool获取shellcode: `asm(shellcraft.sh())`
    - [x] ret2syscall: 没有执行权限时, 可以通过系统调用来实现控制. 
        1. 开启NX保护后, 再如何部署高危代码都没法执行. 所以需要转向利用内核的系统调用实现高危操作. 
        2. 可以通过`/usr/include/asm/unistd_32.h`查看当前内核对应的系统调用号. 比如`#define __NR_execve 11`, 也就是`execve`的系统调用号为`0xb`
        3. 使用`ROPgadget`可用获取寄存器和字符串的gadget.
           * `ROPgadget --binary rop  --only 'pop|ret' | grep 'ebx' | grep 'ecx'`
           * `ROPgadget --binary rop  --string '/bin/sh'`
           * `ROPgadget --binary rop  --only 'int'`
        4. 使用`flat`来直观地表示ROP链: `flat(['A' * 112, pop_eax_ret, 0xb, pop_edx_ecx_ebx_ret, 0, 0, binsh, int_0x80])` 
           * 形式为: `溢出用的填充数据, gadget1(函数原本的返回地址), value1, gadget2, value2, ... , int 0x80`  
    - [x] ret2libc: 
        - [x] ret2libc1: 跳转到libc的高危代码(`system`)并模拟函数调用
            1. 注意跳转到libc的函数去执行, 需要模拟函数调用, 因此跟gadget在栈上的部署方式不一样, 正确的形式为`PLT地址, 函数返回地址, 函数参数地址...`
            2. 获取`system()`的plt地址方法: `objdump -d ret2libc1 | grep system`, 也就是地址是写在汇编里的.
        - [x] ret2libc2: 如果缺少函数调用的条件(缺少函数参数字符串`/bin/sh`)
            1. 利用libc里的`gets`函数, 并手动输入相应的函数参数字符串即可弥补.
            2. `['a' * 112, gets_plt, pop_ebx, buf2, system_plt, 0xdeadbeef, buf2]`需要注意的是`pop_ebx`作为`gets`的返回地址, 它还将buf2给弹出栈, 使得程序继续向下执行`system`函数部分.
        - [x] ret2libc3: 既没有函数参数字符串(`/bin/sh`)也没有高危libc函数地址(`system`)
            1. libc之间函数偏移是固定的, 因此可以通过某个已知的libc函数偏移, 来获取任意其他libc函数地址. 
            2. libc有延迟绑定机制, 只有执行过的函数它的GOT才是正确的. 
            3. libc内自带有`/bin/sh`字符串. 
            4. 可以利用`__libc_start_main`地址来泄露偏移.
            5. 利用思路就是 => 构造ROP链通过`puts`泄露`__libc_start_main`的got地址 => 使用`LibcSearcher`获取libc的基址从而获取`system`地址和`/bin/sh`地址 => 重载程序 => 构造payload控制.
</details>

<details>
<summary>Day2: 学习CTF Wiki中级ROP和格式化字符串漏洞</summary>

> 传送门: [CTF Wiki: Linux Pwn](https://ctf-wiki.github.io/ctf-wiki/pwn/readme-zh/)

- [x] [Intermediate ROP](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/medium-rop-zh/):
    - [x] [ret2csu](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/medium-rop-zh/#_1):
        * x64寄存器传参的顺序为`rdi, rsi, rdx, rcx, r8, r9`, 超出数量的参数根据函数调用约定压入栈中(比如从右向左压栈)
        * `__libc_csu_init`是`__libc_start_main`调用的用于初始化的函数. 参考: [Linux X86 程序启动–main函数是如何被执行的？](https://luomuxiaoxiao.com/?p=516)
        * 示例的level5应是[ctf-challenges](https://github.com/ctf-wiki/ctf-challenges)里的[hitcon-level5](https://raw.githubusercontent.com/ctf-wiki/ctf-challenges/master/pwn/stackoverflow/ret2__libc_csu_init/hitcon-level5/level5), 而非蒸米提供的[level5](https://github.com/zhengmin1989/ROP_STEP_BY_STEP/tree/master/linux_x64)
        * 使用`ROPgadget`搜索可用的gadget是可以发现, 程序并没有直接的控制传参用的寄存器, 大多都是控制`r12-r15`, 这也就是分析`__libc_csu_init`的关键: 我们需要其中的`mov`语句, 通过`r13-r15`控制x64传参用的前三个寄存器.
        * 分析`__libc_csu_init`的目的是掌握可控制的寄存器, 也就是能控制`rbx, rbp, r12, r13=>rdx, r14=>rsi, r15=>edi`, 同时可控的`r12`和`rbx`以及`call qword ptr [r12+rbx*8]`能控制调用的函数地址(`r12`为函数地址, `rbx`直接为0). `add rbx, 1; cmp rbx, rbp; jnz 400600`则是约束条件`rbx+1==rbp`, 故而`rbx=0则rbp=1`. 这样来看这是一段非常优雅的`gadget`. 
        * `write (fd, &buf, count)`中, linux下`fd=0/1/2`分别对应`stdin/stdout/stderr`. 
        1. libc延迟绑定机制, 因此需要等待`write`输出`Hello, World`后泄露函数地址. 
        2. 泄露函数地址后获取libc基址, 然后获取`execve`地址
        3. 利用csu执行`read()`向bss段写入`execve`地址和参数`/bin/sh`
        4. 利用csu执行`execve(/bin/sh)`
        <details>
        <summary>Q1: 为什么要先<code>read()</code>写<code>execve</code>地址, 而不是直接调用<code>execve</code>函数呢?</summary>
        因为<code>call qword ptr [r12+rbx*8]</code>指令, 实际上我们通过csu控制的是一个地址, 而该地址指向的内容才是真正函数的调用地址. 而<code>read()</code>写到bss段的是<code>execve</code>的地址, 但csu调用的时候提供的是bss段的地址, 这样才能完成函数调用. 如果直接传<code>execve</code>地址, 那么是无法调用成功的.
        </details>
        <details>
        <summary>Q2: 为什么可以用写入的<code>/bin/sh</code>地址能成功, 而直接用libc内的<code>/bin/sh</code>地址就不能成功呢?</summary>
        我一个可能性比较高的推测是, 回顾我们的gadget, 对于x64传参的第一个寄存器<code>rdi</code>, 其实我们的gadget只能控制寄存器<code>rdi</code>的低32位(<code>edi</code>). 而对于bss段地址来说, 它实际上是一个32位的地址(高32位为0), 而libc内的<code>/bin/sh</code>是一个64位的地址(高32位不为0), 所以没有办法传递完整的地址进去. 所以只能通过bss上写入的<code>/bin/sh</code>地址进行传参. 
        </details>
        <details>
        <summary>csu函数实现</summary>

        ``` python
        def csu(func_addr, arg3, arg2, arg1, ret_addr):
           rbx = 0
           rbp = 1
           r12 = func_addr
           r13 = arg3
           r14 = arg2
           r15 = arg1
        
           # pop rbx rbp r12 r13 r14 r15 retn
           csu_pop_gadget = 0x000000000040061A

           # r13=>rdx r14=>rsi r15=>edi 
           # call func
           # rbx+1 == rbp
           # add rsp, 8
           # csu_pop_gadget
           csu_mov_gadget = 0x0000000000400600

           # pop 6 registers and `add rsp, 8`
           stack_balance = b'\x90' * 0x8 * (6+1)

           payload = flat([
               b'\x90'*0x80, b'fake_rbp', p64(csu_pop_gadget),
               p64(rbx), p64(rbp), p64(r12), p64(r13), p64(r14), p64(r15),
               p64(csu_mov_gadget), stack_balance, p64(ret_addr)
           ])

           io.send(payload)
           sleep(1)
        ```
        </details>
    - [x] [BROP](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/medium-rop-zh/#brop): 盲打的方式通过程序是否崩溃来推测信息. 适用于Nginx, MySQL, Apache, OpenSSH等服务器应用, 因此该攻击还有着一定的实际应用价值.
        > 理论知识主要参考 [Blind Return Oriented Programming (BROP) Attack-攻击原理](https://wooyun.js.org/drops/Blind%20Return%20Oriented%20Programming%20(BROP)%20Attack%20-%20%E6%94%BB%E5%87%BB%E5%8E%9F%E7%90%86.html), 示例程序参考 [HCTF2016-出题人失踪了(brop)](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/brop/hctf2016-brop)
        * 实现攻击必需的2个条件:
            1. 存在栈溢出漏洞, 且攻击者可以通过输入轻松触发. (没有程序没有源码没有信息, 打也打不崩, 那还玩什么)
            2. 程序崩溃后会重新运行, 并且重新运行的进程地址不会再次随机化. (能稳定复现, 获取稳定地址, 包括Stack Canary也不能随机化)
        * 描述了4种gadget:
            1. stop gadget: 程序跳转到该gadget片段后, 程序并没有崩溃, 而是进入某种hang/loop状态, 能与攻击者保持连接. 
            2. (potentially) useful gadget: 找到stop gadget后, 通过一定的内存布局而发现的更多的`不会崩溃`的gadget. (当然包括新发现的stop gadget)
            3. brop gadget: 一种特殊的`useful gadget`, 能帮助我们控制x64传参用的寄存器. 典型示例就是`__libc_csu_init()`尾部的rop链. gadget能通过指令错位(`+7/+9`)的方式得到单独控制`rsi`和`rdi`寄存器的新gadget.
            4. trap gadget: 就是会让程序崩溃的gadget. 
        * 攻击思路:
            1. 通过爆破, 获取程序崩溃时的字符串填充长度. 
            2. 通过单字节枚举, 逐字节地泄露出栈上保存的`Canary`. (当然也可以枚举出栈上保存的寄存器和原本的返回地址.)
            3. 寻找`stop gadget`: 早期能得到的信息只有程序崩溃和不崩溃, 所以我们需要获得第一个程序不会崩溃的stop gadget. 
            4. 寻找`useful gadget`: 通过合理的布局栈上的内存, 我们可以利用`stop gadget`来发掘更多的`useful gadget`, 并且是能确认该`useful gadget`弹栈数量的.
                * 比如栈上的布局情况为: `...| buffer | gadget | trap x N | stop | trap|...`  则表明该gadget有`N`个pop指令(`N=0,1,...`).
            5. 从`useful gadget`里筛选出真正有帮助的`brop gadget`. 这里就以`__libc_csu_init()`的尾部gadget为例, 该gadget能弹栈`6`次, 通常认为符合这种性质的gadget很少, 所以有一定把握去判断, 并且该gadget可以通过错位得到单独控制`rsi`和`rdi`的gadget, 也可以通过`减去0x1a`来获取其上的另一个gadget. 
            6. 寻找`PLT`项. PLT在盲打时有这样的特征: 每一项都有`3`条指令共`16`个字节长. 偏移`0`字节处指向`fast path`, 偏移`6`字节处指向`slow path`. 如果盲打时发现有连续的`16`字节对齐的地址都不会造成程序崩溃, 这些地址加`6`后也不会崩溃. 那么就推断为`PLT`地址. 
            7. 确定`PLT`项内的`strcmp`和`write(也可以是put)`: 
               * 确定`strcmp`的目的在于: 目前只能通过`brop gadget`控制传参用的前2个寄存器(rdi和rsi), 第3个寄存器`rdx`尚且没法用gadget控制. 因此转变思路通过`strcmp`和控制字符串长度来给`rdx`赋值, 变相控制第三个传参用的寄存器.
               * 确定`write`的目的在于: 需要通过`write`将内存代码都写回给攻击者. 通常是将`fd`设置为连接的`socket描述符`. 而`write`需要3个参数, 这也是为什么借用`strcmp`控制`rdx`的原因. 
               * 确定`strcmp`的方法在于控制函数的两个地址: `readable`和`bad(0x00)`地址. 这样就有`4`种参数形式, 并且只有两个参数地址都是`readable`时函数才会正确执行, 其他情况都没有正确执行, 那么就推断这个plt项对应的是`strcmp`. 
               * 确定`write`的方法在于确定写入的`fd`, 就只能尽量枚举文件描述符来测试了. 建议用较大的文件描述符数字. 
               * 如果是寻找`puts`的话, 就比较容易确定. 因为我们只需要控制输出`0x400000`地址的内容, 该地址通常为ELF文件的头部, 内容为`\x7fELF`. 构造的payload形式为`buffer |pop_rdi_ret | 0x400000 | puts_addr | stop`. 
            8. 有能力控制输出函数后, 攻击者可以输出更多的.text段代码. 也可以去寻找一些其他函数, 比如`dup2`或`execve`等:
               * 将`socket`输出重定向到`stdin/stdout`.
               * 寻找`/bin/sh`, 或者利用`write`写入到某块内存.
               * 执行`execve`或构造系统调用. 
               * 泄露`puts`在内存的实际地址, 然后确认libc基址, 获取`system`地址并构造rop链.
- [x] [Format String Vulnerability](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/fmtstr/fmtstr_intro-zh/):
    * 格式化字符串漏洞的本质在于信任了用户的输入, 攻击者通过输入构造好的格式化字符串来泄露栈上的内存数据.
        * `%x`或`%p`用于泄露栈内存数据.
        * `%s`用于泄露变量对应地址的内容, 存在`\x00`截断.
        * `%n$x`用于泄露输出函数的第`n+1`个参数. 这里的`n`是相对于格式化字符串而言的. 
    * 可以通过`func@plt%N$s`将内存中的`func`实际地址泄露出来. `N`表示其在栈上相对格式化字符串而言是第`N`个参数.
    * 确定了偏移后, 使用`...[overwrite addr]....%[overwrite offset]$n`. `%n`写入的值可通过增加输出的字符数量进行调整.
    * 覆写的地址没有位置的要求, 只需要找到对应偏移即可. 
    * 利用`%hhn`进行单字节写入, `%hn`进行双字节写入.
</details>

<details>
<summary>Day3: 回顾软件安全保护技术和学习ARM汇编基础</summary>

- [x] 软件保护技术: 
    - [x] 反调试:
        * 利用WinAPI检测调试状态: [IsDebuggerPresent](https://ctf-wiki.github.io/ctf-wiki/reverse/windows/anti-debug/isdebuggerpresent-zh/).
        * 内存数据检查: 比如通过`PEB`的字段(`BeingDebug`), 堆上的标志信息([Heap flags](https://ctf-wiki.github.io/ctf-wiki/reverse/windows/anti-debug/heap-flags-zh/))来检测调试.
        * 调试驱动检测: 基于一些使用了驱动的调试器的行为特征, 比如`调试器会在启动后创建相应的驱动链接符号`, 来确定是否存在调试器.
        * [进程窗口检测](https://ctf-wiki.github.io/ctf-wiki/reverse/windows/anti-debug/example-zh/#_3): 比如枚举当前所有进程名/窗口名来检查是否存在已知调试器.
        * 特征码检测: 枚举当前所有正在运行的进程, 匹配特定调试器的内存代码数据来判断是否有调试器. 
        * [时间差检测](https://ctf-wiki.github.io/ctf-wiki/reverse/windows/anti-debug/example-zh/#_2): 通过调试和非调试模式下程序运行的时间差异来判断是否存在调试. 
        * 断点检测/[异常检测](https://ctf-wiki.github.io/ctf-wiki/reverse/windows/anti-debug/example-zh/#seh): 断点检测在于判断内存代码是否被修改为`int3`, `int 2d`等软中断指令, 异常检测在于故意触发异常,如果调试器接管了异常则认定为存在调试器.
        * 功能破坏: 基于大部分程序通常都不会使用系统提供的调试功能这一假设, 保证程序正常运行的前提下, 破坏系统提供的调试相关功能. 比如在创建线程时指定`ThreadHideFromDebugger`属性可以隐藏线程引发的异常, 接收不到异常调试器就无法正常工作. 
        * 双进程保护: 基于一个进程只能同时被一个调试器调试的前提, 以调试方式启动被保护的程序, 通过占用调试行为的方式来阻止攻击者去调试分析受保护程序.
    - [x] 反虚拟机: 
        * BIOS信息检测: 虚拟机软件厂商的BIOS通常具有明显的品牌特征. 
        * 字符串特征检测: 虚拟机产品明显的字符串特征.
        * [后门端口检测](https://ctf-wiki.github.io/ctf-wiki/reverse/windows/anti-debug/example-zh/#vmware): 比如VMWARE的后门I/O端口`0x5658("VX")`读取数据得到`VMXh`
    - [x] 数据校验:
        * 文件校验: 实现计算好程序文件的校验值, 然后运行时再校验比对判断文件本身是否被修改. 
        * 内存校验: 通常程序运行时, `.text/.rsrc`等区段是不会修改的, 通过运行时计算内存数据的校验值来判断内存数据是否被修改.
    - [x] 导入表加密: 保护导入表能阻止攻击者去获取对应的符号信息, 增大分析难度. 
        1. 可以简单地劫持导入表函数调用处来隐藏调试器/反汇编器提供的符号信息.
        2. 也可以预先将导入表函数地址加密存储到某个位置, 然后将导入表RVA指向解密代码, 解密代码运行后得到真实的函数地址, 并跳转过去执行.
        3. 另一种方式就是, 将导入表函数的入口代码进行加密或虚拟化, 在运行时解密.
        4. IAT模拟: 自己实现一些程序可能调用的外部函数, 然后替换导入表内的原始函数.
    - [x] 模块拷贝移位: 用于对抗代码Hook的技术, 方法是复制移位模块, 然后映射模块内的数据到内存以及重定位, 替换原模块函数调用地址.
    - [x] 资源加密: 
        1. 在程序运行时将资源解压/解密, 然后修正PE文件头的资源指向.
        2. Hook各种与资源相关的函数, 然后在调用函数时动态解密资源.
    - [x] 代码加密: 代码加密的目的是将原始代码转换为等价的, 极其复杂的, 更多的代码. 
        * 代码膨胀/变形: 将1条或多条指令转变为等价的其他指令, 更多是用于膨胀. 
        * [垃圾代码(花指令)](https://ctf-wiki.github.io/ctf-wiki/reverse/windows/anti-debug/junk-code-zh/): 目的也是膨胀, 但是方式就是插入无用的或者干扰(误导)调试器反汇编算法的代码. 
        * 代码乱序(平坦化): 通过跳转指令打乱指令的正常顺序, 增大分析难度.
        * 多分支: 也是花指令的一种, 只是这里的花指令着重在分支跳转指令上, 这些分支跳转大部分是根本不会执行的deadcode, 但是会让攻击者在分析时难以确定代码的具体执行流程.
        * call链: 通过call指令来打乱执行流程. 
    - [x] 代码虚拟化: 设计一套虚拟机和对应的opcode来在保证语义的前提下, 模拟原本的指令. 
        虚拟机本质也是程序代码, 运行虚拟机本身也会影响当前的上下文, 因此虚拟机设计时需要保存/恢复上下文, 解决虚拟机和原始代码在上下文的使用冲突. 通常有以下两种方案:
        * 堆机: 开辟新的栈空间来运行虚拟机代码, 代码执行完后恢复原始的栈空间地址即可. 
        * 栈机: 不开辟新空间, 在原有栈空间分出一部分专门给虚拟机使用, 并避免原始指令影响到虚拟机专用的栈空间.
    * 脚本引擎: 将程序的部分功能分交给脚本引擎解释执行.
    * 网络加密: 将程序的部分代码放到服务器执行, 服务器只返回代码的执行结果. 
    * 硬件加密: 类似网络加密, 只是将关键数据/代码转移到了硬件介质里.
    * 代码签名: 利用签名严重算法, 对程序文件数据进行签名, 将对这些签名的校验作为能否运行该软件的判断条件.
- [x] [ARM汇编基础](https://azeria-labs.com/writing-arm-assembly-part-1/)
    - [x] [Introduction to ARM Assembly](https://azeria-labs.com/writing-arm-assembly-part-1/)
        * ARM为RISC指令, 相比CISC具有精简的指令和更多的通用寄存器.
        * ARM只能使用操作寄存器的指令, 并且使用`Load/Store`模型访问内存(也就是只有`Load/Store`指令能访问内存). 
        * 指令精简可以带来更快的运行速度, 但同时在可用指令有限的情况下难以高效地编写软件. 
        * ARM有两种模式`ARM模式`和`Thumb模式`. `Thumb模式`下的指令长度既可以是`2字节`也可以是`4字节`.
        * `ARMv3`前使用`小端`, 之后支持`双端`并且可以切换字节序.
    - [x] [Data Types Registers](https://azeria-labs.com/arm-data-types-and-registers-part-2/)
        * `s`后缀表示`signed`, `b`表示`byte`长度为8, `h`表示`halfword`长度为16. ARM的`word`是`32`位长.
        * 大小端的切换由`CPSR`寄存器的第`9`位`E`来指示. 
        * 寄存器数量取决于ARM的版本. 通常有`30`个32位寄存器, 前`16`个寄存器用户模式下可用, 其他寄存器只有特权模式下可用. 
          * `R0-R6`为通用寄存器, 其中`R0`对应`EAX`
          * `R7`用于保存系统调用号
          * `R8-R10`也是通用寄存器
          * `R11(FP)`类似于`EBP`, 也就是栈基寄存器
          * `R12(IP)`即`Intra Procedural Call`内部过程调用寄存器.(x86没有接触过呢)
          * `R13(SP)`类似于`ESP`, 也就是栈顶寄存器
          * `R14(LR)`:即`Link Register`, 链接寄存器
          * `R15(PC)`: 程序计数器, 类似于`EIP`.
          * `CPSR`: 当前程序状态寄存器, 类似于`EFLAGS`.
        * ARM上的函数调用约定: 前四个参数存储在寄存器`R0-R3`中.
        * 链接寄存器`R14(LR)`: 据[解释](https://baike.baidu.com/item/%E9%93%BE%E6%8E%A5%E5%AF%84%E5%AD%98%E5%99%A8/8767852?fr=aladdin), `LR`实际上是函数调用时用于保存函数的返回地址, 意义在于快速进入和返回`叶函数`. 
        * 程序计数器`R15(PC)`: ARM模式下指令长度为4, Thumb模式下长度为2. PC会根据所处模式来递增相应的指令长度. 执行分支指令时, 会将分支跳转的目的地址保存到`PC`. 但程序执行过程中, `PC`存储的总是当前执行指令的`后2条`指令(ARM模式就+8, Thumb模式就+4).
</details>

<details>
<summary>Day4: 学习ARM汇编基础和CTF Wiki的花式ROP</summary>

> 传送门: [azeria-labs](https://azeria-labs.com/writing-arm-assembly-part-1/) / [ROP Tricks](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/fancy-rop-zh/)

- [x] [ARM Assembly](https://azeria-labs.com/writing-arm-assembly-part-1/)
    - [x] [ARM Instruction Set](https://azeria-labs.com/arm-instruction-set-part-3/)
        * ARM模式亦或是Thumb模式跟所处的特权等级无关. 
        * 开发ARM Shellcode时需要尽量避免`NULL`空字节出现, 因此常用Thumb指令
        * ARM版本之间会有略微差别, 需要根据对应版本查询[官方文档](http://infocenter.arm.com/help/index.jsp)
        * Thumb有三个版本:
            1. Thumb-1: 16比特长, 用于ARMv6及早期版本
            2. Thumb-2: 16/32比特长, 扩展了Thumb-1, 支持更多的指令. 适用于`ARMv6T2`和`ARMv7`.
            3. ThumbEE: 包括一些对动态生成代码的变化.
        * ARM和Thumb指令的区别:
            1. 条件执行: ARM所有指令都可以条件执行, Thumb只能通过`IT`指令允许部分指令有条件地执行.
            2. 32位表示: 32位的Thumb指令会多一个`.w`的后缀
            3. 桶式移位器(ARM独有特性): 能用于精简指令. 
        * 要切换处理器执行状态, 需要满足以下两者条件其一:
            1. 使用分支指令`BX`或`BLX`并将目标寄存器的最低有效位设置为`1`(通过`+1`实现)
            2. 状态寄存器置位T
        * ARM汇编指令格式`MNEMONIC{S}{condition} {Rd}, Operand1, Operand2`. 注意`Operand2`的使用稍有灵活, 并且有些指令中`Operand1`是隐含的.
    - [x] [Memory Instructions: Loading and Storing Data](https://azeria-labs.com/memory-instructions-load-and-store-part-4/)
        * `[pc, #12]`表示`pc`相对寻址. 不过要注意, ARM里的`pc`指的是当前指令的下`2`条指令位置, 也就是ARM模式下`+8`, Thumb模式下`+4`
        * 地址模式: offset / pre-indexed / post-indexed
            * 以`立即数`作为偏移的情况:
                * `str r2, [r1, #2]`: 地址模式: offset. 直接将r2寄存器中的值存到`r1+2`所表示的地址处. `r1`没有变化
                * `str r2, [r1, #4]!`: 地址模式: pre-indexed(`!`是一个标识的特征). 类似offset寻址模式, 寻址`r1+4`, 寻址存储完执行`r1=r1+4`
                * `ldr r3, [r1], #4`: 地址模式: post-indexed. 寻址`r1`, 寻址完执行`r1=r1+4`
            * 以`寄存器`作为偏移的情况: 类似立即数作偏移的情况, 很好理解. 
            * 以`移位寄存器`作为偏移的情况: 类似立即数作偏移的情况, 不过移位的优先级是最高的, 比如`str r2, [r1, r2, LSL#2]`就是将r2内的值保存到`r1+r2<<2`的地址处.
        * ARM使用立即数: ARM使用立即数的方式很不灵活, 格式为`v = n ror 2*r` 其中`n in [0-255]`, `r in [0-30]`. 对于不能合规的立即数, 考虑拆分成两个更小的数加起来, 或者使用`LDR`指令比如`LDR r1, =511`
    - [x] [Load and Store Multiple](https://azeria-labs.com/load-and-store-multiple-part-5/)
        * 多次加载/存储可以使用`LDM`和`STM`指令
        * `LDM`和`LDR`的方向是相反的, 同样`STM`和`STR`方向也相反
        * 扩展`-IA (increase after), -IB (increase before), -DA (decrease after), -DB (decrease before)`
        * `PUSH`和`POP`和x86汇编基本一致. 
        * `PUSH`等价于`STMDB sp! reglist`
        * `POP`等价于`LDMIA sp! reglist`
    - [x] [Conditional Execution and Branching](https://azeria-labs.com/arm-conditional-execution-and-branching-part-6/)
        * 分支条件在标志寄存器中会相应地置位, 这点跟x86一致, 区别主要在标志寄存器各个位的含义略有不同. ARM的分支通过在指令后加相应的条件码来实现.
            | Condition Code | Meaning (for cmp or subs) | Status of Flags  |
            | ---- | -- | -- |
            | CS or HS | Unsigned Higher or Same (or Carry Set) | C==1 | 
            | CC or LO | Unsigned Lower (or Carry Clear) | C==0 |
            | MI | Negative (or Minus) | N==1 |
            | PL | Positive (or Plus) | N==0 |
            | AL | Always executed | - |
            | NV | Never executed | - |
            | VS | Signed Overflow | V==1 |
            | VC | No signed Overflow | V==0 |
            | HI | Unsigned Higher | (C==1) && (Z==0) |
            | LS | Unsigned Lower or same | (C==0) || (Z==0) |
        * `IT`是`IF-Then-(Else)`的缩写.
        * `IT`指令格式: `IT{x{y{z}}} cond`, 也就是最多可以有条件地执行`4`条指令
            * `cond`指定`IT`块中第`1`条指令的条件
            * `x`指定第`2`条指令的条件, `y`指定第`3`条, `z`指定第`4`条
        * `IT`块里`T`的条件要跟`I`保持一致, `E`的条件要跟`I`和`T`相反. (这也很好理解, 就是ARM划分分支的一种形式)
        * 条件码的反义就不硬背了, 直接看`ITE`就可以判断`IT`块里的情况. 
        * `branch`指令跟x86的类似, 只是助记符不一致, 理解还是很好理解的. 
            * `B`: 单纯跳转分支
            * `BL`: 将`PC+4`保存到`LR`然后跳转分支
            * `BX/BLX`: 相比多了一个`Exchange`, 也就是切换指令集(`ARM <-> Thumb`)
            * `BX/BLX`通常会使用类似`add r2, pc, #1; bx r2`的方法先取`pc`然后`+1`的方法使最低有效位置为1(`0`转ARM，`1`转Thumb), 然后用`BX/BLX`切换指令集. (这里不用担心内存块对齐`4`的问题, CPU会自动屏蔽没有对齐的那个bit1/0). 
    - [x] [Stack and Functions](https://azeria-labs.com/functions-and-the-stack-part-7/)
        * 栈的部分不必多说
        * 函数部分熟悉`Prologue`, `Body`和`Epilogue`
            * `prologue`: `push {r11, lr}; add r11, sp, #0; sub sp, sp, #16`
            * `body`: `mov r0, #1; mov r1, #2; bl max`
            * `epilogue`: `sub sp, r11, #0; pop {r11, pc}`
- [x] [ROP Tricks](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/fancy-rop-zh/)
    - [x] [stack pivoting](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/fancy-rop-zh/#stack-pivoting)
        * 直接劫持栈指针指向攻击者的内存, 可以以较少的指令达成攻击, 对于开启PIE保护的程序也可以适用. 
        * 利用的gadget为`pop rsp/esp`, 也可以通过`libc_csu_init`的gadget经过错位获得. 
        * 有办法控制到`esp`后, 还需要想办法将`esp`的值指向写入的shellcode部分. 可以加`\x90`垫.
    - [x] [Stack smash](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/fancy-rop-zh/#stack-smash)
        * Canary检查到溢出后, 程序会执行`__stack_chk_fail`函数打印`argv[0]`指针. 而攻击思路就是借栈溢出覆盖`argv[0]`实现信息泄露. 
        * 攻击需要确定溢出到`argv[0]`所需要的字节数, 以及需要溢出的地址. 
</details>

<details>
<summary>Day5: 学习CTF Wiki整数溢出和堆管理机制</summary>

> 在此前需要了解glibc的堆内存管理器的机制. 主要参考 [glibc内存管理ptmalloc源代码分析](https://paper.seebug.org/papers/Archive/refs/heap/). Seebug有一个[堆资料的归档](https://paper.seebug.org/papers/Archive/refs/heap/)也可以省下找资料的功夫. 

- [x] 整数溢出:
    * 上界溢出: 上界溢出能使得数值变得极小, 有符号整数`正极大=>0`, 无符号整数`正极大=>负极小`
    * 下界溢出: 跟上界溢出相反, 有符号整数`0=>正极大`, 无符号整数从`负极小=>正极大`
    * `错误的类型转换`和`没有严格限制数值范围`是造成整数溢出的两个常见原因. 
- [x] 堆溢出基础:
    * `malloc(size_t n)`:
        * 返回指针, 指向新分配的`至少为n字节`的内存块地址. 
        * 如果`n=0`, 返回系统允许的`最小块`. 通常32位下是`16字节`, 64位下是`24或32字节`. 
        * `size_t`通常是无符号整数, 因此`n<0`会造成整数溢出变成非常大的值, 而malloc通常也会因为分配不了这么大的内存而失败. 
    * `free(void* p)`:
        * 释放由`p`指向的内存块. 
        * 当`p=Null`时, `free`不会进行任何操作
        * `p`被`double free`后造成漏洞. 
        * 当释放很大的内存块时, 会将该内存还给系统
    * 系统调用`(s)brk / mmap`: `malloc`和`free`都是通过系统调用来分配释放内存.
        * `(s)brk`: 可以通过增加`brk`的大小来向操作系统申请内存. 比如`curr_brk = sbrk(0); brk(curr_brk+4096);`就可以在`curr_brk`的基础上新增加`0x1000`的堆内存空间.
        * 查看堆内存可以根据进程的`pid`号去`cat /proc/[pid]/maps`查看.
        * `mmap`: `mmap`相比`brk`的操作粒度更细一些, 有几个可以控制的参数. 类似`mmap(NULL, (size_t)132*1024, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)`
        * `dlmalloc`所有的线程都`共享一个堆`, 因此不支持多线程, 如果两个线程同时申请内存, 就只能一个线程进入`临界区`, 另一个线程等待. 
        * 操作系统倾向于第一次直接分配一个大内存给程序, 避免多次分配内存(切换内核态和用户态)开销. 同时释放的内存也不会立即回收, 而是交由glibc继续管理. 
- [x] [ptmalloc源代码分析](https://paper.seebug.org/papers/Archive/refs/heap/glibc%E5%86%85%E5%AD%98%E7%AE%A1%E7%90%86ptmalloc%E6%BA%90%E4%BB%A3%E7%A0%81%E5%88%86%E6%9E%90.pdf):
    - [x] 基础知识
        - [x] x86平台Linux进程内存布局:
            * 32位Linux会将ELF载入到`0x8048000(128M)`
            * `.bss`段与`stack`之间的空间分为两部分: `heap`和`mmap region`
            * `stack`和`mmap region`都是反向生长(`高地址=>低地址`), `heap`是正向`低地址=>高地址`
        - [x] 操作系统内存分配的相关函数: 
            * 内存的**延迟分配**: 只有在真正访问一个地址的时候才建立这个地址的物理映射. Linux内核在用户申请内存时分配的是一个线性区(虚拟内存), 只有当用户使用这块内存的时候内核才会分配具体的物理页面给用户. 而物理页面的释放也是通过释放线性区, 找到其对应的物理页面, 将其全部释放. 
            - [x] Heap相关函数: 
                * `int brk(void *addr);` brk()是一个非常简单的系统调用, 仅仅只是改变`mm_struct`结构的成员变量`brk`的值
                * `void *sbrk(intptr_t increment);` 注意`increment=0`时, sbrk()返回的是进程当前brk值, `increment>0`时扩展brk, `increment<0`时收缩brk.
            - [x] Mmap相关函数:
                * `void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);` 将一个文件或其他对象映射进内存
                    * `prot`是内存保护标志: 有`PROT_EXEC`, `PROT_READ`, `PROT_WRITE`, `PROT_NONE`.
                    * `flags`: 指定映射对象的类型, 映射选项和映射页是否可以共享. (不太懂什么含义先忽略)
    - [x] 概述: 
        - [x] 内存管理方法: 
            1. C风格的内存管理: 实现`malloc`和`free`函数, 通过调用`brk()`和`mmap()`来管理内存. 但是需要程序员手动管理内存, 繁琐复杂困难. 
            2. 池式内存管理: 为程序的每个特定阶段分配特定的内存. 优点是简单快速易于实现, 缺点是只适用于操作分阶段的程序, 兼容性差难以维护.
            3. 引用计数: 通过标记引用次数来判断数据结构是否存活.
            4. 垃圾回收: 垃圾回收会在可用内存减少到一定程度时才会启动, 首先以程序所知的"可用数据"(栈数据,全局变量,寄存器)出发, 去追踪相应存活的数据. 没有找到的其他数据就被标记为垃圾进行销毁. 
</details>

<details>
<summary>Day6: ptmalloc2内存管理机制(分配和释放)</summary>

- [x] ptmalloc2内存管理概述
    - [x] 内存管理的设计假设
        1. 对`长生命周期`的`大内存`分配使用`mmap`, `特别大`的内存总是使用`mmap`, `短生命周期`的内存分配用`brk`
        2. 尽量缓存临时使用的`空闲小内存块`, `大内存`或`长生命周期`内存释放时则直接返还系统
        3. `空闲小内存`只会在`malloc`和`free`期间进行合并, `free`时空闲内存块`可能放回pool而非返还系统`
        4. 收缩堆的条件: `当前free的chunk大小 + 前后能合并的chunk大小 > 64KB`并且`堆顶的大小达到阈值`
        5. 需要长期存储的程序不适合用ptmalloc管理内存
        6. 多个线程可以从同一个`arena`中分配内存. 
    - [x] 内存管理数据结构
        - [x] `main_arena`与`non_main_arena`
            * Doug Lea实现的内存分配器只有一个主分配区(`main_arena`), 因此每次分配内存为避免竞争都会加锁, 而这样会带来很大开销. 
            * `ptmalloc`增加了多个非主分配区(`non_main_arena`), `main_arena`和`non_main_arena`形成环形链表进行管理. 每一个`arena`利用互斥锁, 使`线程对于该arena的访问互斥`.
            * `main_arena`能访问进程的`heap`和`mmap`映射区域, 而`non_main_arena`只能访问`mmap`映射区域. 
            * 线程申请内存: 先查找线程私有变量看是否已经存在一个arena, 如果有就对该arena加锁然后分配内存, 如果没有, 就去循环链表找没加锁的arena. 如果arena都加锁了, 那么malloc就会开辟新的arena, 将该arena加入循环链表, 用该arena分配内存. 
        - [x] `chunk`的组织
            - [x] 使用中chunk结构:
                ![ptmalloc-busy-chunk.png](assets/ptmalloc-busy-chunk.png)
                * `chunk指针`指向chunk的起始位置, 而`mem指针`才是真正返回给用户的指针. 
                * `P`: 表示前一个chunk是否在使用中. 
                  * `P=0`表示前一个chunk空闲, 这时chunk的第一个域`prev_size`才生效. `prev_size`用于找到前一个chunk的起始地址.
                  * `P=1`表示前一个chunk正在使用中, `prev_size`无效, 无法依据`prev_size`找到前一个块的位置(不会对前一个chunk进行任何操作)
                * `M`: 表示chunk从内存区域分配获得. `M=1`表示从`mmap映射区域`分配, `M=0`表示从`heap区域`分配.
                * `A`: 表示该chunk所属`arena`. `A=1`表示`non_main_arena`, `A=0`表示`main_arena`. 
            - [x] 空闲的chunk结构:
                ![ptmalloc-free-chunk.png](assets/ptmalloc-free-chunk.png)
                * 空闲状态时没有`M`标志. 
                * `fd`指向`后一个空闲的`chunk, `bk`指向`前一个空闲`的chunk. `fd`和`bk`组合成双向链表. 
                * `large bin`中的空闲chunk, 还有额外两个指针`fd_nextsize`和`bk_nextsize`. 用于加快在`large bin`中`查找最近匹配的空闲chunk`. 
                * 不同的chunk链表使用`bins`或`fastbins`来组织. 
            - [x] chunk中的空间复用:
                * chunk之间复用一些无意义的域空间, 以尽量减小chunk所占空间. 
                * 一个chunk正在使用时, 它后一个chunk的`prev_size`肯定是无效的, 就可以把这个空间省下来. `inuse_chunk_size = (用户请求大小+8-4)对齐8`
        - [x] 空闲`chunk`容器
            - [x] `Bins`
                * 用户`free`的内存交由`ptmalloc`管理, 当用户下一次请求内存, ptmalloc就会从空闲内存里挑一块给用户, 减少了系统调用, 也就降低了开销. 
                * `ptmalloc`将`相似大小`的chunk用`双向链表`链接起来, 这样的链表称为`bin`
                * `ptmalloc`一共维护了`128`个bin并组成数组(array), 也就是对应了`128`个size. 
                * 假设数组索引从1开始, `array[1] = unsorted bin`, `array[2:64] = small bins`, `array[65:128] = large bins`
                * `small bins`: 
                    * 两个相邻的`small bin`中的chunk大小相差`8bytes`
                    * `small bin`里的chunk按`头进尾出`进行排列, 新释放的chunk存入链表的`头部`, 新申请的chunk从链表`尾部`取出. 
                * `large bins`: 
                    * 每一个`bin`分别包含`给定范围内的chunk`, chunk按大小排列, 相同大小的chunk按`头进尾出`排列. 
                    * ptmalloc会分配`符合要求的最小chunk`
                * 当空闲chunk链接到bin中, ptmalloc会把该chunk的`P`标志设为`0`(**注意: 这个标志实际上处在下一个`chunk`中**), 同时ptmalloc会检查它`前后的chunk`是否也是空闲的. 如果空闲, 就合并成大的chunk, 然后把合并后的chunk放到`unsorted bin`里去. 
                * 并非所有的chunk被释放后都放到bin中. ptmalloc为了效率会把一些小的chunk先放到`fast bins`里.
            - [x] `Fast Bins`
                * 小内存的分配总是频繁的, `fast bins`就是为此而引入
                * `size < max_fast(64B)`的chunk释放后放入`fast bins`内. 
                * `fast bins`内的chunk不会改变`P`标志位, 这样也就无法将其合并. 
                * 当需要小于`mas_fast`的chunk时, ptmalloc会首先在`fast bins`内找相应的空闲块, 找不到才会去`bins`里找. 
                * 在某个特定时间点, ptmalloc会遍历`fast bins`, 将相邻的空闲chunk进行合并, 将合并后的chunk加入`unsorted bin`中, 然后再将`unsorted bin`中的chunk加入`bins`中
            - [x] `Unsorted Bin`
                * `unsorted bin`可以看做是`bins`的一个缓冲区.
                * malloc时会优先查找`fast bins`, 然后找`unsorted bin`, 然后找`bins`. 
                * `unsoretd bin`找不到合适的chunk, malloc会将`unsorted bin`的chunk加入到`bins`, 然后从`bins`继续查找和分配.
            - [x] `Top chunk`
                * `top chunk`在`main_arena`和`non_main_arena`存在不一致的地方, 具体原因在于`main_arena`是唯一能映射进程heap区域的地方.
                * `top chunk`会在`fast bins`和`bins`都无法满足分配需求的时候使用, 如果`top chunk`也无法满足, 那么就系统调用一块新的, 然后和`top chunk`合并.
            - [x] `mmaped chunk`: 当申请的`chunk`足够大, `top chunk`也无法满足时, ptmalloc会使用`mmap`将页映射到进程空间, 这样的chunk在释放时则直接解除映射将内存返还系统. 
            - [x] `Last remainder`: 当需要分配一个`small chunk`但在`small bins`找不到合适的, 而`last remainder`的大小可以满足, 那么就切割`last remainder`成两个`chunk`, 一个大小合适的chunk返回给用户, 另一个chunk成为新的`last remainder`
        - [x] `sbrk`与`mmap`
            * ptmalloc在最开始时, 如果请求的空间小于`mmap`分配阈值, `main_arena`就使用`sbrk()`来分配内存作为heap. `non_main_arena`则使用`mmap`映射空间作为`sub-heap`. 
            * 之后就根据用户的分配释放来管理内存, 再遇上分配空间不足的情况, `main_arena`继续使用`sbrk`来增加heap大小(申请的大小得小于mmap分配阈值), `non_main_arena`则还是使用`mmap`映射新的`sub-heap`. 
    - [x] 内存分配概述
        1. 分配算法概述:
           * `size < 64B`: 用pool算法
           * `size in 64B...512B`: 在最佳匹配算法分配和pool算法分配取合适的
           * `size >= 512B`: 最佳匹配算法分配
           * `size >= mmap分配阈值(128KB)`: 如果没有动态调整过mmap分配阈值, 就按大于默认的128KB就直接调用mmap. 否则大于调整过的mmap阈值才调用mmap分配
        2. ptmalloc内存分配的具体步骤:
           1. 获取arena的锁: 查看线程私有实例是否存在一个arena => 搜索arena的循环链表找没有加锁的arena => 所有arena都加锁了, ptmalloc开辟新的arena, 将该arena加入循环链表和线程的私有实例并加锁, 然后进行内存分配. 
               * 开辟出来的新arena一定为`non_main_arena`, 因为`main_arena`是从父进程继承而来
               * 开辟新arena需要调用mmap创建一个sub-heap, 并设置好top chunk
           2. 根据用户请求大小计算实际需要分配的chunk大小
           3. 判断申请的chunk大小是否满足 `size <= max_fast`, 满足则使用fastbins分配, 否则继续. 
           4. 判断大小是否在small bins范围内. 是则用small bins分配, 否则继续.
           5. 到此说明需要分配的是大内存. ptmalloc首先遍历fastbins的chunk, 将相邻chunk合并存入`unsorted bin`. 然后在unsorted bin中找合适的chunk切割返回给用户, 否则继续
           6. 从`large bins`里找一块最小满足的chunk. 找不到则继续
           7. 使用`top chunk`分配, 如果`top chunk`也不满足所需chunk的大小, 则继续
           8. 使用`sbrk`或`mmap`来增大`top chunk`的大小以满足分配, 或者直接使用`mmap`来分配内存(这需要满足mmap分配阈值).
    - [x] 内存回收概述
        1. 首先获取arena的锁, 保证线程安全
        2. 判断传入指针是否为0, 为0直接return
        3. 判断释放的hcunk是否为`mmaped chunk`, 是则调用`munmap`释放. 如果开启了mmap分配阈值的动态调整, 且当前回收chunk的大小大于mmap分配阈值, 则将mmap分配阈值设置为该chunk大小, mmap收缩阈值设为mmap分配阈值的2倍, 释放完成. 否则进行下一步
        4. 判断chunk的大小和位置, 若`chunk_size <= max_fast`且该chunk不与top chunk相邻, 则将该chunk放入fastbins中(不修改该chunk的`P`标志, 也不与相邻chunk进行合并), 否则进行下一步
        5. 判断前一个chunk是否处在使用中, 如果前一个chunk也是空闲状态, 则一起合并
        6. 判断后一个chunk是否为top chunk, 如果不是, 则判断后一个chunk是否空闲状态, 空闲则合并, 将合并后的chunk放到`unsorted bin`中. 如果是后一个chunk是top chunk, 那么无论它有多大都一律和top chunk合并, 更新top chunk的大小等信息. 都同样继续以下步骤
        7. 判断合并后的chunk大小是否大于`FASTBIN_CONSOLIDATION_THRESHOLD`, 如果是, 则触发fastbins的合并操作, 合并后的chunk放入`unsorted bin`
        8. 判断top chunk的大小是否大于mmap收缩阈值, 大于的话, 对于main_arena会试图归还topchunk的一部分(最初分配的128KB不会返还)给操作系统. 对于non_main_arena会进行sub-heap收缩, 将top chunk的一部分返还给操作系统. 如果top chunk为整个sub-heap, 会把整个sub-heap返回给系统. 至此释放结束, free()函数退出.
            * 收缩堆的条件是当前free的chunk大小加上前后能合并的chunk的大小大于64K, 并且top chunk的大小要达到mmap收缩阈值, 才可能收缩堆.
</details>

<details>
<summary>Day7: 软件破解技术</summary>

- [x] 静态分析:
    - [x] 基本信息分析: 从三个方面判断程序是否加密
        1. PE程序的区段信息: 正常的PE程序比较规则, 大多是`.text/.data/.rsrc/.reloc`, 而加密后的区段常有明显特征
        2. PE导入表信息: 加密后的导入表往往只有少数的几个dll.
        3. PE程序入口点: 标准编译器编译出来的入口点代码比较规范. 
   - [x] 代码静态分析: 结合工具进行静态分析, 比如`IDA`, .NET程序使用`ildasm IL/.NET Reflector`
- [x] 软件调试:
    - [x] 一般调试原理: 
        * windows内置有调试API和相应的调试事件. 
        * 异常处理流程: 软硬件异常->通过IDT被系统捕获->系统分类异常->交由调试器处理->通过`KiUserExceptionDispatcher`函数交由进程内SHE处理->再次交由调试器处理->触发系统软件异常流程
            * 任何异常, 尤其是软件异常, 都需要内核过滤, 并在保护层和内核层来回切换, 速度相当慢
            * 调试器处理异常的优先级在保护层中是最高的 , 内核无法处理的异常都会优先传递给调试器来处理
        * 调试器一般软断点都是通过人为触发INT3异常来实现
        * 硬件断点通过CPU的DR系列寄存器实现. 因为寄存器数据有限, 因此最多只能同时下`4`个硬件断点.
        * 硬件断点的好处在于无需修改调试指令, 并且执行速度很快. 
        * 内存断点是通过`修改内存页的属性触发访问异常`实现
    - [x] 伪调试技术:
        * 在程序进程内注入代码, 接管`KiUserExceptionDispatcher`函数入口, 从而在改程序处理任何异常前得到对异常的优先处理. 然后代替系统将异常处理的信息转交给外部调试器. 
    - [x] 远程调试: `cdb -server tcp:port=123 -noio c:\windows\notepad.exe`然后用windbg连接远程调试会话. 
    - [x] 虚拟机调试: 连接虚拟机提供的调试接口进行调试
- [x] Hook:
    * 代码Hook: 使用流程控制指令(比如`jmp`或`push/ret`组合指令)来实现对程序流程的控制
    * 模块Hook: 这里的模块可以理解为DLL, `GetModuleHandleA`函数能给定模块名后获得模块对应的基址, 进程每次载入模块, 系统都会维护一张模块的列表, 列表中保存了模块的许多信息其中就包括基址. 而这个列表所在的地址保存在PEB的`LoaderData+C`位置, 而模块链表的结构中的`hashTableList`就是`GetModuleHandleA`所查找的表. 
- [x] 代码注入: 
    1. 暂停的方式启动进程, 这样能保证程序的入口代码尚未被执行
    2. 注入需要在目标进程中执行的额外代码
    3. 设置线程上下文的方式修改主模块入口到额外代码入口. windows下以暂停方式启动一个进程后, 系统会把主模块入口放在线程上下文的eax成员中, 修改该成员即可修改主模块入口地址.
    4. 恢复目标进程并执行
- [x] 补丁:
    * 冷补丁: 直接修改程序中所包含的数据来修改程序执行流程或结果. 
    * 热补丁: 在程序运行过程中直接修改程序所在进程的内存空间数据
    * SMC: 直接修改压缩或加密后数据, 使这些数据被解压或者解密后最终呈现我们所涉及的数据. 
    * 虚拟化补丁: 通过硬件或者软件虚拟将代码运行时执行和读写的代码页分离, 然后通过修改执行页中的数据达到修改程序运行流程的目的. 
- [x] 模块重定位
    * 在Windows进程中, 除了NTDLL模块地址无法直接修改, 其他模块都可以重定位
    * 具体步骤
        1. 通过篡改`ZwOpenSection`函数, 使系统放弃以共享内存段的方式加载一个模块
        2. 通过篡改`ZwMapViewOfSection`函数, 使系统加载模块到指定的基址
        3. 处理特殊模块kernel32
</details>

<details>
<summary>Day8: Linux内核及其内在机理</summary>

> 传送门: [linux-insides](https://github.com/0xAX/linux-insides)

- [x] 从引导加载内核:
    1. 按下电源开关主板供电备妥后, CPU会`复位寄存器的所有数据, 并设置每个寄存器的预定值`. CPU复位后, 寄存器的预设数据如下: `IP=0xfff0, CS=0xffff`. `实模式`下内存寻址时通过段寄存器偏移(实模式CPU只能用16位寄存器)得到, 也即`CS:IP=(0xffff)<<4+0xfff0=0xfffffff0`. 而实模式下CPU是无法访问`0xfffffff0`这个地址的, 所以`0xfffffff0`被映射到了ROM而非RAM. 
    2. `0xfffffff0`是`4GB-16B`, 也就是`复位向量`所在位置, 也就是CPU在重置后期望执行的内存地址入口. 通常为一个`jump指令`, 用于跳往`BIOS入口`
    3. BIOS在初始化和检查硬件后, 需要找到一个`可引导设备`. BIOS会根据BIOS配置里的可引导设备列表顺序, 依次尝试寻找引导程序, 对硬盘而言就会去`MBR分区`, 该分区存储在磁盘第一个扇区(512字节)的头446字节, 引导扇区的最后必须为`0x55`和`0xaa`(这是引导程序的magic标识). 
    4. `MBR`分区代码只能占用一个扇区, 因此非常简单, 只做了一些初始化, 然后就跳转到`GRUB2`的`core image`去继续执行. `core image`的初始化代码会把整个`core image`(包括GRUB2的内核代码和文件系统驱动)引导到内存中. 引导完成后, 调用`grub_main`
    5. `grub_main`初始化控制台, 计算模块基地址, 设置root设备, 读取grub配置文件, 加载模块. 最后将grub置于`normal`模式, 调用`grub_nomal_execute`完成最后的准备工作, 然后显示菜单列出所有可用的操作系统. 
    6. 选择操作系统之后, 执行`grub_menu_execute_entry`, 它会调用grub的`boot`命令, 来引导选择的系统.
    7. 引导会根据`kernel boot protocol`的描述, 填充`kernel setup header`里的字段, 将内核引导入内存后, 交由Kernel继续执行. Kernel的代码从`0x1000 + X + sizeof(KernelBootSector) + 1`开始执行(`X`是kernel bootsector被载入内存的基址)
- [x] 内核引导和设置
    1. 首先需要正确设置内核, 内核设置代码的运行起点为`arch/x86/boot/header.S`的`_start`函数. 在`_start`之前还有一些kernel自带的bootloader代码, 主要是兼容`UEFI`. 
    2. `_start`第一句就是`jmp`语句, 跳转到其后的相对地址(`start_of_setup-1f`), 也就是`_start`后第一个标号为`1`的代码, 该部分包含了剩下的`setup header`结构. 而`1`之后就是`start_of_setup`的代码, 该部分开始会完成`段寄存器设置`, `堆栈设置`, `bss段设置`, `跳转到main.c开始执行代码`的工作
    3. `段寄存器设置`: 将`ds`和`es`寄存器的内容设置为一样, 通过利用`lretw`将`ds`寄存器的值放入`cs`寄存器
    4. `堆栈设置`: 检查`ss`寄存器的内容, 如果内容不对则进行更正
    5. `设置BSS段`: 检查`magic`签名`setup_sig`, 如果签名不对直接跳转到`setup_bad`执行相应代码. 如果签名正确, 就设置好`BSS`段将其全部清零. 
    6. `跳转到main函数`: `calll main`. main()定义在`arch/x86/boot/main.c`
- [x] 保护模式
    * 保护模式相比实模式, 有32位地址线能访问`4GB`的地址空间并且引入了内存分页的功能. 
    * 保护模式提供了2中完全不同的内存管理机制: `段式内存管理`和`内存分页`. 
    * 实模式下物理地址由`内存段的基地址`和`基地址开始的偏移`组成, 也即`segement << 4 + offset`. 但在保护模式下, 每个内存段不再是64K大小, 段的大小和起始位置通过`段描述符`描述, 所有内存段的段描述符存储在`全局描述符表(GDT)`结构里. 
    * `全局描述符表(GDT)`在内存位置并不固定, 它的地址保存在特殊寄存器`GDTR`里. 使用指令`lgdt gdt`将`GDT`的基地址和大小保存到`GDTR`寄存器中. `GDTR`是一个`48`位寄存器, 该寄存器保存2部分内容: `GDT的大小16位`和`GDT的基址32位`. 
    * 而保护模式下, 段寄存器保存的`不再是内存段的基地址`而是称为`段选择子`的结构. `段选择子`对应了相应的`段描述符`. 段选择子是一个16位的数据结构, 包含了对应`段描述符的索引号`, `选择是在GDT还是LDT查找段描述符`, 和`请求优先级`. 
    * 保护模式下, CPU通过以下步骤找到寻址:
        1. 将相应`段选择子`载入段寄存器
        2. 根据`段选择子`从`GDT`中找到匹配的`段描述符`, 然后将段描述符放入段寄存器的隐藏部分. 
        3. 在没有向下扩展段的时候, 内存段的基地址, 就是段描述符中的基地址. 
    * 代码从实模式切换到保护模式的步骤:
        1. 禁止中断发生
        2. `lgdt gdt`
        3. 设置CR0寄存器的PE位为1, 使CPU进入保护模式
        4. 跳转执行保护模式代码.
- [x] main函数操作:
    1. 将启动参数拷贝到`zeropage`: 调用`copy_boot_params(void)`, 该函数将`内核设置信息`拷贝到`boot_params`结构的相应字段. 
    2. 控制台初始化: 调用`console_init`. 
       1. 该函数先查看命令行参数是否包含`earlyprintk`选项. 
       2. 如果包含, 函数将分析这个选项的内容, 得到控制台将使用的`串口信息`并进行`串口初始化`. 
       3. 串口初始化成功后, 如果命令行参数带有`debug`选项, 可以看到一行输出`early console in setup code`
    3. 堆初始化: 内核需要初始化全局堆, 通过`init_heap`实现
       1. 首先检查`内核设置头`的`loadflags`是否设置`CAN_USE_HEAP`标志. 如果设置了该标志, 代码会计算`栈的结束地址`和`堆的结束地址`
       2. 栈的结束地址计算: `stack_end = esp - STACK_SIZE`
       3. 堆的结束地址: `heap_end = head_end_ptr + 0x200`
       4. 判断`heap_end`是否大于`stack_end`. 如果大于, 那么就把`stack_end`设置为`heap_end`(栈和堆的生长方向相反, 这里设置让堆和栈相邻, 增大了栈的底部空间, 不影响栈逆向生长)
       5. 这样就完成了全局堆的初始化, 全局堆初始化之后, 就可以使用`GET_HEAP`方法了.
    4. 检查CPU类型: 调用`validate_cpu`检查CPU是否可用. `validate_cpu`会调用`check_cpu`得到当前系统的`cpu_level`并和系统要求的最低`cpu_level`比较, 如果不满足就不允许系统运行. 
    5. 内存分布侦测: 调用`detect_memory`进行内存侦测, 得到系统当前内存的使用分布. 以下是`detect_memory_e820`(该方法的多种接口之一, 用于获取全部内存分配)原理:
       1. 调用`initregs`方法初始化`biosregs`数据结构, 然后向该数据结构填入`e820`接口所要求的参数. 
       2. 通过循环收集内存信息. 循环结束后整个内存分配信息被写入到`e820entry`数组, 数组元素包含三个信息: `内存段起始地址`, `内存段大小`, `内存段类型`. 可以使用`dmesg`查看到这个数组的内容
    6. 键盘初始化: 调用`keyboard_init()`方法进行键盘初始化. 首先调用`initregs`初始化寄存器结构, 然后调用`0x16`中断获取键盘状态, 获取状态后再次调用`0x16`中断来设置键盘的按键检测频率. 
    7. 系统参数查询: 内核进行一系列的参数查询, 依次是:
       1. `query_mac`调用`0x15`中断来获取机器的型号, bios版本和其他硬件相关信息. 
       2. `query_ist`获取`Intel SpeedStep`信息, 首先检查CPU类型, 然后用`0x15`中断获取该信息并填入`boot_params`中
       3. `query_apm_bios`从BIOS获取电源管理信息. 
       4. `query_edd`从BIOS查询硬盘信息. 
</details>

<details>
<summary>Day9: Android安全里的攻防和分析知识</summary>

> Android安全部分参考[《Android安全攻防实战》](https://book.douban.com/subject/26437165/)

- [x] APK结构:
  * 证书签名
    * 证书文件在APK解压后的`META-INF`文件夹内.
      * `CERT.RSA`是公钥证书的自签名. 
        * 使用`keytool`进行检查: `keytool -printcert -file CERT.RSA`, 其中有声明`公钥的持有者`.
        * 使用`openssl`进行检查: `openssl pcks7– inform DER –in META- INF/ CERT. RSA –noout –print_ certs –text` 
        它指定了以下5个信息
        * `Owner`: 公钥持有者, 包含与该个体相关的国家组织信息
        * `Issuer`: 声明该证书的颁发机构. 
        * `Serial number`: 证书的标识符
        * `Valid from...until`: 指定证书有效期, 其关联属性可以由颁发者验证
        * `Certificate fingerprints`: 记录证书的数字校验和, 用来验证证书是否经过村阿盖
      * `CERT.SF`包含了APK中各个资源文件的SHA-1哈希. 使用`jarsigner`验证apk内容时就会比对该文件. 
      * `MANIFEST.MF`: 声明资源文件
    * 如何对App签名?
      1. 创建`keystore`, 用于存放签名app所使用的私钥: `keytool –genkey –v -keystore [keystore名称] –alias [私钥别名] –keyalg RSA –keysize 2048 –validity [有效天数]`
      2. 使用`keystore`通过`jarsigner`对app签名: `jarsigner –verbose –sigalg MD5withRSA –digestalg SHA1 –keystore [keystore文件] [你的.apk文件] [私钥别名]`
    * 如何验证app签名? `jarsigner –verify –verbose [apk文件]`
  * `AndroidManifest.xml`: 声明app的权限和组件信息
    * 如何提取`AndroidManifest.xml`? `apktool d -f -s [apk文件] [解压目录]`
  * adb命令:
    * `adb logcat`: 显示调试日志
    * `adb shell pm list packages`: 列出设备中所有package
    * `am start [Activity名]`: 启动指定activity.
      * 对于intent可以使用`-e key value`传递字符串键值
      * 对于service可以使用`am startservice`启动
- [x] APP中的漏洞:
  * logcat信息泄露: logcat里泄露了一些网址信息(http(s))或者cookie信息
  * 检查网络流量:
    1. 在设备上使用`tcpdump`和`nc`捕获流量: `tcpdump -w - | nc -l -p 31337`
    2. 使用adb命令将设备的流量转发到本地端口: `adb forward tcp:12345 tcp:31337`
    3. 本地`nc`连接转发端口: `nc 127.0.0.1 12345`
    4. `wireshark`连接管道获取流量: `nc 127.0.0.1 12345 | wireshark -k -S -i -`
  * 通过`am`被动嗅探`intent`: TODO 需要使用`drozer`
  * 攻击service: 
    1. 搜索哪些service是exported
    2. 尝试运行这些service. 运行的同时使用`logcat`来查看它是否会在运行时泄露一些敏感信息
    3. 如果想通过intent向service发送数据, 你需要去了解它的`intent filter`. 
    4. 某些service可能作为原生库的接口, 将intent接受的数据转换成类似基于堆/栈的数据结构, 这可能会造成内存溢出漏洞
  * 攻击broadcast receiver:
    * 发掘receiver的漏洞需要确定`输入是否可信`以及该`输入的破坏性如何`. 
    * 需要阅读源码, 弄清楚receiver的`intent filter`
- [x] 保护APP:
  * 保护APP组件: 正确使用`AndroidManifest.xml`以及在代码级别上强制进行权限检查
    * 尽量减少`android:exported`属性的使用, 尽可能地减少暴露的组件
    * android 4.2之前, 或者sdk版本17以下, 定义的`intent-filter`元素默认是导出的.
  * 定制权限: 指定组件的`android:permission`和定义`permission-group`
  * 保护`provider`组件:
    * 设置权限`android:permission`
    * 设置读相关权限(query): `android:writePermission`
    * 设置写相关权限: `android:readPermission`
    * 使用`path-permission`元素为单独的路径(比如`/[path]`)设置不同的权限, `path`的权限设置优先级更高
  * 防御SQL注入: 确保攻击者不能注入恶意构造的SQL语句
    * 避免使用`SQLiteDatabase.rawQuery()`, 而是改用一个参数化的语句(参数化的意思就是指定一个语句的格式, 并非指定参数, 而是描述性的表达语句, 可以类比为格式化字符串, 比如`insert into TABLE_NAME (content, link, title) values (?,?,?)`). 
    * 使用一个预先编译好的语句, 比如`SQLiteStatement`, 提供对参数的绑定(binding)和转义(escaping). 
    * 使用`SQLiteDatabase`提供的`query`, `insert`, `update`和`delete`方法. 
  * 验证app的签名: 根据事先计算好的签名哈希, 在代码运行时进行比对来判断文件是否被篡改
  * 反逆向工程方式: 
    * 检测安装程序: 比如检查安装程序是否为谷歌商店
    * 检查是否出于模拟器中: 获取相应的系统特征字符串进行判断
    * 检查app的调试标志是否启用: 启用调试标志意味着app可能连上了adb进行调试
    * 利用JAVA的反射API能在运行时检查类, 方法及成员变量, 这使得能够绕过访问控制修饰符(`access modifier`)的限制, 调用正常情况下无法使用的东西. 
  * 使用`ProGuard`: `ProGuard`是Android SDK自带的开源java代码混淆器.
    * `ProGuard`会把程序执行时不需要的信息都删除掉, 比如代码中不使用的方法, 域, 属性和调试信息
    * 它会把一些代码优化成更短更难以阅读的混淆代码
  * 使用`DexGuard`进行高级代码混淆
    * 相比`ProGuard`不仅能混淆Java代码, 还能保护资源文件和Dalvik字节码
    * API隐藏: 使用`API反射机制`隐藏对敏感API和代码的调用
    * 字符串加密: 对源代码的字符串进行加密
    * 反射调用会把类名和方法名包存为字符串, 而字符串加密可以结合起来将这些反射字符串加密起来. 
- [x] 逆向app
  * java源码编译成dex:
    1. `javac -source 1.6 -target 1.6 example.java`
    2. `dx --dex --output=example.dex example.class`
  * dex文件格式: 可以使用`dexdump example.dex`进行解析
    * magic(8bytes): `dex\n035`
    * checksum(4B): 表示dex文件的`Adler32`校验和, 用于验证dex文件头是否被篡改. 
    * SHA签名(20B)
    * fileSize(4B): 表示整个dex文件的长度
    * headerSize(4B): 表示整个DexHeader结构的长度, 单位为byte
    * endianTag(4B): 存放的是固定值, 在所有dex文件中都意义. 为`0x12345678`, 根据这个值在内存的排列顺序来判断是大端序还是小端序.
    * linkSize和linkOff: 多个.class被编译到一个dex时会哟感到
    * mapOff
    * stringIdsSize: 存放StringIds区段大小. 
    * stringIdsOff: 存放stringIds区段的实际偏移, 帮助Dalvik编译器和虚拟机直接跳转到该区段而不用计算偏移. 
    * StringIds区段实际上保存的是各个字符串的地址
    * TypeIds区段则是存放了各个类型描述符在stringIds列表的索引号. 
    * ProtoIds区段存放一系列用来描述方法的prototype id, 其中含有关于各个方法的返回类型和参数信息
    * FieldIds区段由一些stringIds和typeIds区段中数据的索引号组成, 用于描述类中各个成员
    * MethodIds区段用于描述方法, ClassDefs区段用于描述类
    * 除开用`dexdump`对dex解析, 还可以使用`dx`, 不过你得有相应的class文件: `dx -dex -verbose-dump -dump-to=[output].txt [input].class`
  * 反汇编/反编译/gdb调试操作:
    * 将dex反汇编得到smali代码: `baksmali example.dex`
    * 将dex反编译得到.class文件: `dex2jar example.dex`
    * 将.class反编译得到java代码: 使用jd-gui
    * 反汇编native so文件: 使用android ndk的toolchain提供的arm版本objdump. `arm-linux-androideabi-objdump -D [native library].so`
    * gdb调试正在运行的android进程:
      * `mount`会输出每个块设备都是怎么mount的一些信息
      1. `mount -o rw,remount [device] /system`
      2. `adb push [NDK-path]/prebuilt/android-arm/gdbserver/gdbserver /system/bin`
      3. 使用`ps`确定要调试的进程PID, 使用gdbserver进行attach: `gdbserver :[tcp-port] --attach [PID]`
      4. 转发android设备的TCP端口: `adb forward tcp:[remote_port] tcp:[local_port]`
      5. 本地运行交叉编译好的`arm-linux-androideabi-gdb`然后输入`target remote :[local_port]`来连接端口
- [x] SSL安全:  验证SSL签名证书: 利用OpenSSL
  1. 对于网络上的自签名证书, 使用`openssl s_client -showcerts -connect server.domain:443 < /dev/null`显示该证书的详细信息, `BEGIN CERTIFICATE`到`END CERTIFICATE`部分为证书内容, 将其保存为`mycert.crt`
    * 使用openssl创建自签名证书: `openssl genrsa -out my_private_key.pem 2048`生成.pem的私钥文件, 然后用该私钥生成证书: `openssl req -new -x509 -key my_private_key.pem -out mycert.crt -days 365`
  2. 得到`mycert.crt`后, 我们要将证书打包到app中, 就需要创建证书并将其导入到`.keystore`文件中, 该文件会被视为`truststore`.
  3. 使用`Bouncy Castle`库创建并导入证书到truststore:
    1. 设置`CLASSPATH`环境变量: `$ export CLASSPATH=libs/bcprov-jdk15on-149.jar`
    2. 使用`keytool`创建并导入公钥证书
        ``` bash
        $ keytool -import -v -trustcacerts -alias 0 / 
          -file < ( openssl x509 -in mycert.crt) / 
          -keystore customtruststore.bks / 
          -storetype BKS / 
          -providerclassorg.bouncycastle.jce.provider.BouncyCastleProvider /
          -providerpath libs/bcprov-jdk15on-149.jar \
          -storepass androidcookbook
        ```
    3. 输出文件是添加了公钥证书的`customtruststore.bks`(bks为Bouncy Castle Keystore). 保护口令为`androidcockbook`
    4. 复制`customtruststore.bks`到app的raw文件夹去. 
    5. 在app代码里从raw文件夹中加载本地truststore到一个KeyStore对象里去. ? 书里将保护口令硬编码了出来, 但是该口令只是用于验证truststore的完整性, 不是用来保护其安全性. 而且truststore是服务器的公钥证书
- [x] Android原生代码的漏洞分析
  * 检查文件权限: 寻找权限设置不正确或存在问题的文件
    * 列出"所有用户均可读取的文件": `find [path-to-search] -perm 0444 -exec ls -al {} \;`
    * 列出"所有用户均可写的文件": `find [path-to-search] -perm 0222 -exec ls -al {} \;`
    * 列出"所有用户均可执行的文件": `find [path-to-search] -perm 0111 -exec ls -al {} \;`
    * 列出"setuid位设为1的可执行文件": `find [path-to-search] -perm -4111 -exec ls -al {} \;`
    * 列出所有属于"root"用户的文件: `find [path-to-search] -user 0 -exec ls -al {} \`
  * 交叉编译原生可执行程序: 创建Android.mk文件和JNI文件夹, 利用NDK提供的`ndk-build`进行编译.
  * 条件竞争漏洞. 攻击者利用条件竞争漏洞需要满足以下条件:
    1. 能访问和恶意修改存在漏洞的进程所要竞争访问的资源: 如果攻击者无法访问到竞争的资源, 那么是不能引发漏洞的. 当有访问能力时, 进程内所有不适用互斥的独占式访问就都可以利用, 而且进程不检查信号量或自旋锁就直接使用某个指针指向数据的情况发生的非常频繁
    2. 使用时间/检查时间(TOU/TOC)的窗口大小: 本质上是应用程序请求访问一个资源和实际访问到该资源之间的时间差. 竞争条件漏洞利用非常依赖于该时间差, 因为利用的本质就是在这个时间差内竞争到资源的访问权, 以恶意地影响资源.
  * fuzzing: 使用`Radamsa`进行模糊测试 
</details>

<details>
<summary>Day10: 阅读软件供应链安全相关论文</summary>

- [x] [软件供应链安全综述](http://jcs.iie.ac.cn/xxaqxb/ch/reader/view_abstract.aspx?file_no=20200106&flag=1) 
  - [x] 软件供应链的定义: 
    * 商品与服务: 软件
    * 供应者: 软件供应商
    * 消费者: 软件用户
    * 资源: 软件设计开发各阶段编入软件的代码,模块和服务
    * 加工: 编码过程, 工具和设备
    * 渠道: 软件官网和第三方平台 
  - [x] 软件供应链安全的定义: 软件设计开发过程中本身的`编码过程/工具/设备`以及供应链上游的`代码/模块/服务的安全`, 以及`软件交付渠道安全`的总和. 
  - [x] 软件供应链安全发展历程:
    1. 1984年, `K. Thompson`提出`KTH`攻击, 在难以发现的情况下修改编译器并设置后面, 污染所有通过此编译器编译并发布的软件. 
    2. 2004年, 微软提出`SDL安全开发生命周期`流程, 将软件开发划分为多个阶段并在每个阶段引入相应安全措施, 保障软件开发安全并建立漏洞发现和处理框架机制. 
    3. 2010年, `R.J. Ellison`和`C. Woody`提出`软件供应链风险管理`的概念, 介绍了相关分享的来源,总类,分享分析的方法, 威胁模型, 并讨论了应对风险的措施. 
    4. 2015年`XcodeGhost`开发工具污染事件. 攻击者注入病毒污染了非官方渠道发布的Xcode, 使得编译出的app会将运行过程中收集到的敏感信息发送到攻击者服务器. 
    5. 2017年6月`NotPetya`勒索病毒事件. 攻击者通过劫持软件的`升级更新渠道`, 使得用户更新软件时下载并感染了`NotPetya`勒索病毒.
    6. 2017年`CCleaner`恶意代码植入事件. 攻击者入侵公司开发环境, 篡改了编码过程中使用的`CRT函数库`并置入后门代码. 同年7月`Xshell`也以类似手段植入恶意代码.
    7. 2017年8月`WireX` Android僵尸网络事件. 攻击者将病毒与普通安卓app捆绑和伪装, 避过了Google Play对app的检测, 用户下载后感染为僵尸主机. 
  - [x] 供应安全的三个环节四个攻击:
    * 三个环节: 开发环节, 交付环节, 使用环节. (还可以增加一个运营环节)
    * 四个攻击: `开发环节的开发工具攻击`, `开发环节的源代码攻击`, `交付环节的分发渠道攻击`和`使用环节的升级补丁攻击`
  - [x] 软件供应安全研究技术:
    1. 软件漏洞挖掘和分析手段
      * 基于源代码: 使用静态分析方法对源代码进行脆弱性检测
      * 基于模糊测试: 使用黑盒测试手段, 动态挖掘漏洞
      * 基于代码特征: 根据已发现的漏洞提取漏洞特征然后检测目标是否含有该特征.
      * 软件漏洞位置匹配: 确定软件存在漏洞后需要方法匹配识别定位漏洞. 
      * 上游模块漏洞分析: `测量依赖关系/代码复用关系`, 结合`知识流网络/知识图谱`, 对软件模块进行分析. 
    2. 恶意软件及模块的识别和清除手段
      * 恶意特征提取: 基于`统计分析`以及`机器学习`方法对恶意代码静态分析. 
      * 模块恶意篡改: `注入恶意代码`和`重打包/捆绑`是污染供应链的主要方式
      * 比较篡改: 基于`图比较算法`分析相似二进制文件间的差异
    3. 网络劫持的检测和防御手段: 劫持或篡改软件的`交付/维护`渠道: 目前软件的交付和使用阶段高度依赖于网络环节, 因此网络劫持是污染供应链的关键技术. 
    4. 用户端软件安全机制
- [x] [Constructing Supply Chains in Open Source Software](https://dl.acm.org/doi/pdf/10.1145/3183440.3183454)
  * 论文对开源软件设计了三种类型的网络图
    * 用于检查`软件包/库`的`依赖`网络图
    * 用于检查`commit/文件/代码片段`的`代码复用`网络图
    * 用于检查复杂软件的`知识流`网络
  * 构建网络遇到的问题:
    * 共同问题: 
      1. 不同平台的数据格式是`异构`的
      2. 同一平台可能需要支持多种版本控制系统, 比如Github也支持SVN
      3. 公开数据可能并不完整或者说是过时的. 
    * 单独问题:
      1. 依赖网络: 建立依赖关系的分类存在困难
      2. 代码复用网络: 代码复用的检测存在困难
      3. 知识流网络: 确定知识流的属性存在困难
         1. 如何设置流的权重?
         2. 如何确定流的方向?
         3. 作者提出了一个公式来解决该问题
  * 如何构建网络?
    * 依赖网络: 分析语言的`import`和`depend`
    * 知识流网络: 未说明
    * 代码复用网络: 分析git里的`blob`
- [x] [Detecting repackaged smartphone applications in third-party android marketplaces]
  - [x] 重打包apk的两个共同特征
    1. 原始APK与重打包APK之间的代码库存在相似性
    2. 由于开发者签名密钥没有泄露, 因此原始APK和重打包APK必须使用不同的开发者密钥进行签名
  - [x] 特征提取: 
    * 提取`class.dex`里的字节码, 保留字节码指令中的`操作码`. 同时出于实践考虑, 大部分的重打包都是捆绑广告, 因此作者对常用广告SDK库做了白名单将其筛去. 
    * 使用`META-INF`目录获取开发者签名证书, 其中包括有开发者名称, 联系方式, 组织信息和公钥指纹等. 
  - [x] 生成指纹: 使用序列通过模糊哈希算出指纹, 然后通过指纹的距离来判断序列的相似性. 模糊哈希的另一个好处就是能通过哈希更改的地方来确定相应代码的改动区域
  - [x] 相似度评估: 计算两个指纹的编辑距离(参考`spamsum`算法). 但距离超出阈值则认为不相似. 
  * 一个笑点: 作者在实验过程中发现了QQ的一个版本要求了更多的权限, 但是权限的滥用是不足以证明这个apk就是重打包(植入代码)的恶意程序. 我想这里其实也有可能是因为作者从Google Play商店下载了QQ认定为良性, 从国内的平台下载了QQ发现滥用权限. 但通常QQ在国内就是滥用权限,而在国外为了通过Play商店审核而避免了权限滥用, 所以造成了论文中的乌龙现象. 当然后续的分析表明, 它应该确实是一个植入恶意代码的apk, 会跟c2服务器通信.
</details>

<details>
<summary>Day11: 阅读软件供应链安全相关论文</summary>

- [x] [Towards Measuring and Mitigating Social Engineering Software Download Attacks](https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_nelms.pdf)
  * 社工攻击主要分为两类, 一类是重打包良性软件(捆绑软件或其他潜在恶意程序), 一类是警告用户正在使用的`Adobe Flash`或`Java`以及过时或不安全, 而要求用户下载伪造的更新. 
- [x] [软件供应链污染机理与防御研究](http://gb.oversea.cnki.net/KCMS/detail/detail.aspx?filename=1018097481.nh&dbcode=CMFD&dbname=CMFDREF)
  * 污染技术研究
    * 开发环境污染
      1. 源代码污染: 以CCleaner为例, 攻击者入侵公司服务器, 在开发环境里的CRT静态库函数内植入了恶意代码. 并且植入的代码并非开发人员编写的源代码, 因此难以被发现
      2. 开发工具污染: 以XCode为例, 从非官方渠道下发植入恶意代码的Xcode工具.
      3. 第三方开发包污染: 以pypi为例, 主要是通过名称的相似来迷惑受害者. 
    * 软件捆绑污染
      * 众多未授权的第三方下载站点, 云服务, 共享资源, 破解版软件等共同组成了灰色软件供应链. 而通过灰色软件供应链获取的软件极易被攻击者植入恶意代码. 
      * 而一些正规下载站也会因审核不严格而被攻击者上传恶意软件
      * Android的应用通过二次打包生成篡改后的app, 并且用户容易将罪名怪罪给app的开发者. 
    * 网络劫持污染
      * 软件下载时劫持污染: 用户到软件下载服务器之间形成一条数据链路, 攻击者通过中间人的方式进行攻击, 影响传输的数据, 进而对用户下载的软件造成污染
      * 软件升级时劫持污染: 攻击者在中间网络中, 通过URL劫持的放啊, 对多款软件升级时的下载URL进行劫持, 跳转到攻击者的服务器上, 进而导致下载了恶意如那件.
    * 运行环境污染
      * 污染软件运行环境, 比如python, java, php
- [x] [程序逆向分析在软件供应链污染检测中的应用研究综述](http://www.cnki.com.cn/Article/CJFDTotal-JSJY202001018.htm)
  * 程序逆向分析
    * 传统恶意代码分析技术使用的特征主要分为`语法特征`和`语义特征`两大类. 
      * 语法特征需要通过解析程序的二进制指令, 并转换成高级语言(反汇编, 反编译)
      * 语义特征包括`API调用`和`执行过程中系统状态改变情况`
    * 动态分析的瓶颈在于覆盖率邮箱, 很容易受到干扰. 对此提出了`路径探索`和`透明分析`技术
      * 路径探索时应用最广泛的提高动态分析覆盖率的方法. 该技术通过求解不同路径约束的程序输入, 引导程序控制流向更高覆盖率方向转移
      * 透明分析着力于构建被分析样本无法感知的分析系统, 防止被分析程序因为检测到分析环境而不再执行恶意行为. 
  * 供应链安全中的挑战:
    * 程序分析需要能处理多样化的软件发布形式, 并从这个提取相应的城固县进行分析
    * 分析系统需要能自动执行或解压安装包, 成功释放程序可执行文件, 并监控整个安装和程序执行过程. 
    * 输入形式的多样化, 比如配置文件, UI交互, 网络通信, 与操作系统交互等. 这些致使动态分析方法很难自动发现并提供有效输入. 而且异步处理时常用的编程技术, 尚未有静态分析方法能理解各种异步编程模型并准确还原程序逻辑或控制流转移关系
    * 现有工作多出于语法分析层面, 少有工作能自动准确理解程序语义. 
</details>


<details>
<summary>Day12: 学习知识图谱知识, 掌握ES和Neo4j的使用</summary>

- [x] ElasticSearch
  * ES里可以将`index`理解为数据库(`index`的名称必须小写), `index`里的单条记录称为`Document`, `Document`可以分组(`Type`), 分组实际上是一种过滤的手段. 
  * 使用`elasticsearch`和`elasticsearch_dsl`进行操作
- [x] 知识图谱
  * 在信息的基础上, 建立实体之间的联系, 就能形成知识
  * 每条知识用一个三元组表示(subject-predicate-object)
  * 知识图谱的架构:
    * 逻辑结构
    * 分为`模式层`和`数据层`
      * 数据层主要由一系列事实组成, 而知识将以事实为单位进行存储. 
      * 模式层构建在数据层智商, 通过本体库来规范数据层的一系列事实表达
    * 体系架构
  * 知识抽取: 从公开的半结构化, 非结构化数据中提取处实体, 关系, 属性等知识要素
    * 面向开放的链接数据, 通过自动化技术抽取出可用的知识单元
    * 知识单元主要包括`实体`, `关系`和`属性`
      * 实体抽取: 从原始语料中自动识别出命名实体. 
      * 关系抽取: 结局实体间语义链接的问题. 
      * 属性抽取: 通过属性形成对实体的完整勾画
  * 知识融合: 消除实体, 关系, 属性等指称项与事实对象之间的其一, 形成高质量的知识库
    * 由于知识来源广泛, 存在知识质量良莠不齐, 来自不同数据源的知识重复, 知识间的关联不够明确等问题, 所以需要进行知识的融合. 
    * 将不同源的知识进行异构数据整合, 消歧, 加工, 推理严重, 更新等步骤达成融合
  * 知识推理: 在已有的知识库基础上进一步挖掘隐含的知识, 从而丰富, 扩展知识库
  * 技术上, 知识图谱的难点在于NLP, 因为需要机器理解海量的文字信息. 但工程上, 难点在于知识的获取和融合.
- [x] Neo4j
  * 使用`py2neo`进行操作
  * 连接图: ` graph = Graph('bolt://localhost:7687', username='neo4j', password='neo4j')`
  * 创建节点: `a = Node('label', name='a')`, 进行绘制`graph.create(a)`
  * 建立关系: `r1 = Relationship(a, 'to', b, name='goto')`
</details>

<details>
<summary>Day13: 学习Neo4j的CQL语法以及使用python操作es</summary>

> 传送门: [Neo4j教程](https://www.w3cschool.cn/neo4j/)

- [x] Neo4j:
  * 优点: 容易表示连接的数据, 检索/遍历/导航连接数据容易且快速, 容易表示半结构化数据
  * 构建模块:
    * 节点: 节点是图表的基本单位, 包含具有键值对的属性
    * 属性: 用于描述图节点和关系的键值对
    * 关系: 用于连接两个节点, 具有方向, 关系也有属性
    * 标签: 用于描述节点和关系, 是一个分类
  - [x] CQL:
    * CREATE: 用于创建节点, 关系和标签, 要注意, CREATE始终都会创建新的节点
      * 创建没有属性的节点: `CREATE (<node-name>:<label-name>)`
      * 创建具有属性的节点: `CREATE (<node-name>:<label-name>{<Property1-name>:<Property1-Value>})`
      * 还可以用于创建关系和标签
    * MATCH: 用于获取匹配到的数据
      * `MATCH (<node-name>:<label-name>)`
      * 不过MATCH不能单独使用, 需要进行配合
    * RETURN: 用于节点的属性, 关系的属性
      * `RETURN <node-name>.<property1-name>`
      * 同MATCH意义不能单独使用 
    * MATCH+RETURN: MATCH可以和RETURN组合使用: `MATCH Command \n RETURN Command`
    * 创建关系: `CREATE (p1:Profile1)-[r1:LIKES]->(p2:Profile2)`
      * `CREATE (<node1-name>:<label1-name>)-[(<relationship-name>:<relationship-label-name>)]->(<node2-name>:<label2-name>)` 
    * WHERE: 用于过滤MATCH的结果, `WHERE <condition> <boolean-operator> <condition>`, condition的格式为`<property-name> <comparison-operator> <value>`
    * DELETE: 用于删除节点和关系, `DELETE <node-name-list>` 这里的list是用MATCH返回得到的, 也可以是用`,`分隔的多个节点名
    * SET: 用于设置或修改属性, 用法与DELETE类似 
    * REMOVE: 用于删除属性和标签: 用法与DELETE类似
    * ORDER BY: 用于对MATCH结果进行排序, `ORDER BY  <property-name-list>  [DESC]`
    * UNION: 用于将结果合并, 要求结果的名称/数据类型都必须匹配, `<MATCH Command1> UNION <MATCH Command2>`
    * LIMIT: 用于限制MATCH返回结果的行数, 它修剪CQL查询结果集底部的结果, `LIMIT <number>`
    * SKIP: 同LIMIT, 不过是修剪了结果集顶部的结果
    * MERGE: `MERGE = CREATE + MATCH`, MERGE会在创建节点前进行查重, 如果重复了就不会插入新节点.
    * NULL值: CQL里将NULL视作为`缺失值`或`未定义值`, 很多没有指定的地方都会用NULL进行缺省
    * IN: `IN[<Collection-of-values>]`, 类似python的in, 用于确定范围
    * 函数:
      * String函数: `UPPER/LOWER/SUBSTRING/REPLACE`
      * AGGREGATION函数: `COUNT/MAX/MIN/SUM/AVG`
      * 关系函数: `STARTNODE/ENDNODE/ID/TYPE`
    * 索引: `CREATE INDEX ON :<label_name> (<property_name>)`
    * UNIQUE约束: `CREATE CONSTRAINT ON (<label_name>) ASSERT <property_name> IS UNIQUE`
</details>

<details>
<summary>Day14: 学习知识图谱构建技术和阅读两篇应用知识图谱于安全分析的论文</summary>

> 传送门: [自底向上——知识图谱构建技术初探](https://www.anquanke.com/post/id/149122)

- [x] 知识图谱构建技术:
  * 知识图谱: 是结构化的语义知识库, 用于描述概念及相互关系, 实现知识的推理
  * 构建方式: 
    * 自顶向下: 借助已有的结构化数据源(比如百科类), 从高质量数据中提取本体和模式信息, 加入到知识库
    * 自底向上: 从公开采集的数据中提取出资源模式, 选取其中置信度高的信息加入到知识库
  * 逻辑架构:
    * 数据层: 存储真实具体的数据
    * 模式层: 在数据层之上, 存储经过提炼的知识.
  * 技术架构: 构建知识图谱是一个迭代更新的过程, 每轮迭代包括三个阶段
    * 信息抽取: 从多源异构数据源中提取出实体, 属性及相互关系
    * 知识融合: 在获得新知识后, 需要进行整合, 以消除矛盾和歧义. 
    * 知识加工: 对于融合后的新知识, 需要进行质量评估, 将合格的部分加入到知识库中, 确保知识库的质量
- [x] [一种基于知识图谱的工业互联网安全漏洞研究方法](http://www.qczk.cnki.net/kcms/detail/detail.aspx?filename=WXJY202001004&dbcode=CRJT_CJFD&dbname=CJFDAUTO&v=)
  * 从ISVD这样的半结构化信息源里提取了漏洞信息条目. 
  * 信息提取引擎将漏洞信息, 事件信息和产品信息从原始信息中提取出来, 以下是提取规则
    * 通过正则表达式, 提取描述中的`时间`
    * 模糊匹配提取产品的相关描述
  * 关联分析: 建立事件到漏洞的关系, 再建立产品到漏洞的关系, 推导处事件到产品的关系.
- [x] [数据驱动的物联网安全威胁检测与建模](http://kns.cnki.net/kcms/detail/detail.aspx?filename=1020606498.nh&dbcode=CMFD&dbname=CMFDTEMP&v=)
  * 知识融合: 将表示相同内涵但是名称不一致的实体统一成一个名称表示. 
    * 实体层融合首先生成候选物联网安全实体, 主要有基于名称词典, 基于搜索引擎的方法
    * 其次, 候选实体排序. 主要为有监督和无监督的排序方法
    * 最后, 无链接指称项预测, 当知识库里没有相关的候选实体项时, 需要给出近似的实体
  * 知识推理: 包含基于符号的推理和基于统计的推理
    * 基于符号: 通过指定规则, 从已有关系中归纳出新的规则
    * 基于统计: 利用机器学习方法, 通过统计规律从知识图谱中可以有效发现一些网络异常和攻击, 挖掘安全威胁的隐藏关系和路径, 并对攻击进行预测, 从而感知并展示网络的安全态势. 主要包括实体关系学习方法, 类型推理方法和模式归纳方法. 
</details>

<details>
<summary>Day15: 阅读模糊测试资料和掌握Radare2用法</summary>

> 传送门: [The Fuzzing Book](https://www.fuzzingbook.org/), [A journey into Radare 2](https://www.megabeets.net/a-journey-into-radare-2-part-1/#Getting_radare2)

- [x] [Fuzzing: Breaking Things with Random Inputs](https://www.fuzzingbook.org/html/Fuzzer.html#Fuzzing:-Breaking-Things-with%C2%A0Random%C2%A0Inputs): 讲述了简单的随机数生成Fuzzer及其构造, 并通过简单的代码示例介绍了比如内存溢出, 信息泄露的问题, 还有一些内存检查ASAN和assert来帮助检查错误的方法.
- [x] Radare2
  * 一些常用的选项:
    * -a arch 指定架构
    * -A 运行aaa命令用以进行完整的分析
    * -b bits 指定比特数
    * -B baddr 指定载入基地址
    * -c cmd 指定要执行的radare命令
    * -d 进入调试模式
    * -i file 运行指定的脚本
    * -k os 指定os (linux, macos, w32, netbsd, ...)
    * -l lib 载入插件
    * -p project 使用指定工程
    * -w 以write模式打开文件
  - [x] rabin2: 可以从二进制中提取`Sections, Headers, Imports, Strings, Entrypoints`信息, 支持多种文件格式`ELF, PE, Mach-O, Java CLASS`
    * `rabin2 -I file`: 显示二进制的基本信息
  * radare2命令:
    * `ie`: 显示程序入口点信息(info entrypoint)
    * `fs`: 显示可用的标记, `fs symbols; f`可以打印相应标记空间里的信息
    * `iz`: 显示data段里的字符串, `izz`可以打印整个二进制内的字符串
    * `axt`: 找到引用该地址的地方, `axf`则是找到该地址引用的目的地址. 注意现在需要指定`fs`进行搜索了. `fs strings; axt @@ str.*` 
    * `@@`: 可以理解为for-each
    * `afl`: analyze function list, 显示分析处的函数列表
    * `s`: seek, 可以进入到相应的函数或地址, 函数名可以用上面的`afl`给出
    * `pdf`: print diasm function, 显示函数的汇编指令
      * `pdf @ sym.beet`可以用于显示指定函数的汇编
    * `V`: 进入Visual Mode, 使用`p/P`切换模式,
    * `Visual Mode`下的操作:
      * `k`和`j`: 跟vim一样进行上下移动
      * `Enter`: 在jump和call指令的时候, 可以用于进入到目的地址
      * `u`: 返回上一个地址
      * `x/X`: 显示交叉引用, x表示到达该指令的引用, X表示该指令所引用的地方
      * `: command`用来执行shell命令
      * `;[-]comment`: 用来增加/移除注释
      * `m<key>`: 用来标记某个具体的偏移并用某个按键来绑定
      * `q`: 退出visual mode
    * `VV`: 进入`Visual Graph`模式, 就是直接看控制流图
    * `Visual Graph`下的操作:
      * `hjkl`进行移动
      * `g`进入函数, 在graph里很多函数后面都有一个按键的标记, 按下就能进入该函数
    * `ahi`: 用于做数据的类型转换, 比如将某个地址的数据转换成字符串类型`ahi s @ <addr>`
    * `ood`: 重新以Debugger模式打开文件, 可以带参数, 比如`ood args1`
    * `dc`: debug模式下执行, 类似`continue`命令, 会继续执行
</details>

<details>
<summary>Day16: 了解代码覆盖率和程序分析研究进展</summary>

- [x] [Code Coverage](https://www.fuzzingbook.org/html/Coverage.html)
  * 黑盒测试用于测试特定条件的结果. 优势是能够针对特定输入检查错误, 劣势是无法达到很好的覆盖率. 
  * 白盒测试则会尽量满足覆盖率, 起码满足语句和分支的覆盖. 优势是能针对已实现的行为进行测试, 而劣势就是无法满足未能实现的行为. 
  * py通过trace的方式将执行的代码行信息汇总起来得到覆盖率. 而c代码可以通过gcov获取覆盖率情况
- [x] [程序分析研究进展](http://kns.cnki.net/kcms/detail/detail.aspx?filename=RJXB201901006&dbcode=CJFQ&dbname=CJFDTEMP&v=)
  * 抽象解释: 通过对程序语义进行不同程度的抽象以在分析精度和计算效率之间取得权衡. 
  * 数据流分析: 通过分析程序状态信息在控制流图的传播来计算每个静态程序点(语句)在运行时可能出现的状态
    * IFDS/IDE 数据流分析框架: IFDS将数据流分析问题转换为图可达问题, 从而有效进行上下文敏感的过程间分析. 
      * IFDS基于程序过程检控制流图定义了一个超级流图, 其中每个节点对应在一个程序点的抽象域中的一个元素, 而节点间的边表示该元素在过程间控制流图的传播, 对应着数据流分析中的转移函数. 
      * 通过求解是否存在从程序入口到每个程序点的可达路径, 我们可以得到该程序点的状态信息.
    * 基于值流图的稀疏数据流分析方法
      * 传统数据流分析在cfg上将所需计算的状态信息在每个程序点传播得到最终分析结果, 这个过程中通常存在较多冗余操作. 为了提高效率, 提出了多种稀疏的分析方法从而不需计算状态信息在每个程序点的传播而得到和数据流分析相同的结果. 
      * 该技术通过一个稀疏的值流图直接表示程序变量的依赖关系, 从而使得状态信息可以有效地在该稀疏的值流图上传播. 值流图保证了状态信息有效传播到其需要使用该信息的程序点, 并避免了无效程序点的冗余传播, 可大幅提高效率. 
  * 移动应用软件
    * 污点分析: 动态污点分析TaintDroid通过修改的Dalvik虚拟机, 在应用的java字节码解释执行过程中进行动态插装以实现对敏感数据的跟踪分析
  * 二进制代码
    * 递归遍历反汇编: 无法准确识别间接跳转指令的跳转目标
      * 提出基于程序切片技术将间接跳转表进行规范化表示, 根据启发式特征识别间接跳转语句的目标
      * 提出通过在CFG上进行数据流分析, 进而完善CFG, 再迭代式进行数据流分析, 逐步完善CFG. 
      * 提出通过动态分析识别间接跳转的目标, 并采用强制执行的方式驱动程序探索所有路径, 从而构建相对完整的控制流图. 
      * 提出通过RNN识别二进制程序中的函数便捷
    * 高级语义恢复: 二进制程序大量信息确实. 
      * 提出采用NLP类似技术识别二进制程序汇总的函数特征(参数类型和个数)
      * 提出通过切片, 提取函数调用指令的操作数的规范化表示, 根据启发式特征识别虚函数调用点
      * 提出识别程序中静态已知的全局地址, 栈偏移等识别全局变量和栈变量, 通过数据流分析识别间接内存读操作的返回结果等. 实现对二进制程序中的内存访问操作语义的识别. 
      * 提出通过数据流分析, 跟踪this指针的流向, 识别候选的类成员函数及变量, 从而恢复c++对象
    * 代码插装/改写
      * 在原始二进制程序中静态修改: 挑战是反汇编的准确率, 不正确的反汇编会使得插装后程序执行异常
      * 将二进制程序提升到IR再修改: 插装在IR上完成, 与二进制的指令集无关
      * 在代码执行过程中动态修改: 通过受控的执行环境, 在目标基本块, 函数执行前进行插装
    * 匹配漏洞模式
      * 静态分析组件间调用关系, 与恶意代码特征进行匹配, 从而识别安卓恶意代码
  * 面向智能合约的程序分析
    * 符号执行被用于字节码层面检测智能合约中的已知类型的潜在漏洞
    * 相比传统软件, 智能合约的体量较小, 使得对其使用形式化技术称为可能. 
    * 有的工作甚至直接将智能合约代码转换已有的验证系统所支持的形式, 借助已有验证系统快速形成分析, 比如将智能合约代码转换为LLVM字节码
  * 面向深度学习软件的程序分析
    * 由于广泛存在的概率模型, 多层传播的复杂网络结构, 黑盒形式的用户借口等特性, 深度学习工具的质量难以度量, 现有的软件分析技术难以直接应用.
    * 提出了面向深度学习的动态符号执行方法, 该方法将测试需求表示为量化线性运算, 以神经元覆盖为目标测试深度神经网络的鲁棒性. 

</details>

<details>
<summary>Day17: 了解基于变异的模糊测试技术和Python的代码简洁之道</summary>

- [x] [Mutation-Based Fuzzing](https://www.fuzzingbook.org/html/MutationFuzzer.html)
  * 基于变异的模糊测试: 通过微小的变异, 使得输入能够有效地触发新的行为
  * 完全的随机生成有效输入需要的运行次数极其巨大, 因此思路转变为从有效输入中进行变异获取输入
  * 每次变异都是微小的改动, 比如插入一个字符, 删除一个字符, 翻转比特等等
  * 我们需要去引导有价值的变异, 抛弃无效的变异, 所以这里引入覆盖率作为模糊测试的指标进行判断哪个变异更好

- [x] [clean-code-python](https://github.com/zedr/clean-code-python): 
  * 使用有意义且可发音的变量名. 
  * 对于同一个类型的变量尽量统一使用相同的词汇来描述: 主要是避免多种说法带来的不一致和混淆, 增加维护的成本. 如有必要, 还可以进一步封装成类通过getter和setter使用
  * 尽量不要使用硬编码: 或者类似魔数, 因为这样的硬编码数据很难进行管理, 并且也失去了它的表征含义. 
  * 尽可能多的使用带有信息的变量, 少用索引表示. 因为索引很难体现出它的涵义, 如有可能尽量用字符串索引.
  * 减少不必要的上下文信息: 在我已经知道这是个什么东西的时候, 它的属性或成员就没有必要再重复这个信息. 不用犹豫直接把它去掉, 不要带来信息的冗余. 
  * 使用默认参数(缺省值)来替代短路或条件. 
  * 尽量减少函数的参数个数, 2个或更少为宜, 如果超出了, 那么可以考虑将函数代码进行拆分. 
    * 使用`from typing import NamedTuple`和`from dataclasses import astuple, dataclass`在类构造的时候非常优雅!
  * 一个函数, 一个功能: 尽量保持一个函数只实现一个功能, 这样能方便维护和重构
  * 使用生成器能让代码在简洁的同时减少内存占用
  * 不要将标志(flags)/模式(mode)作为函数参数: 将其作为函数参数说明你在该函数内实现了多个功能, 请保持一个函数一个功能的原则, 将其拆分开来. 
  * `SRP: Single Responsibility Principle`: 单一职责原则. 将不同的职责分离到单独的类中, 当需求变化时, 这个变化可以通过更改职责相关的类来实现. 如果一个类拥有多于一个的职责, 这些职责就耦合在了一起, 那么就会有多于一个原因来导致这个类的变化. 对于某一职责的更改可能会损害类满足其他耦合职责的能力, 这样的耦合会导致设计的脆弱, 以致于职责发生改动时产生无法预期的变化. 
  * `OCP: Open/Closed Principle`: 开闭原则. 一个软件实体如类, 模块和函数应该对扩展开放, 对修改关闭. 当修改需求时, 应该尽量通过扩展来实现变化, 而不是通过修改已有代码来实现变化. 
  * `LSP: Liskov Substitution Principle`: 里氏替换原则. 任何父类可以出现的地方, 子类一定可以出现.  
  * `ISP: Interface Segregation Principe`: 接口隔离原则: 使用多个隔离的接口, 优于使用单个接口, 这可以降低类之间的耦合度
  * `DIP: Dependence Inversion Principle`: 依赖倒转原则: 高层模块不应依赖低层模块, 两者都应该依赖其抽象, 抽象不应该依赖细节, 细节应该依赖抽象. 

</details>

<details>
<summary>Day18: 了解灰盒模糊测试技术和阅读二进制重写的论文</summary>

- [x] [Greybox Fuzzing](https://www.fuzzingbook.org/html/GreyboxFuzzer.html):
  * AFL通过轻量级的插装来获取输入的分支覆盖情况. 如果某个输入提高了覆盖率, 那么就将它扔回种子池做更多变异. 
  * AFL的插装是通过在每一个跳转指令处插入一小段代码, 执行时会为执行的分支分配一个唯一的标识符, 并递增该分支的计数器. 出于性能考虑值统计粗略的分支名字次数. 
  * 插装在程序编译阶段完成, 同样对于无法插装的代码(黑盒)也能通过QEMU或Intel Pin来运行AFL
  * `Power Schedules`: 能量调度. 用于为有趣的种子分配更多的能量. 
- [x] [Binary Rewriting without Control Flow Recovery](https://www.comp.nus.edu.sg/~abhik/pdf/PLDI20.pdf)
  * 二进制重写需要恢复控制流主要是因为可能会移动指令, 所以需要控制流信息. 
  * 论文提出了`E9Patch`, 它可以在不需要移动指令的情况下将跳转指令插入到函数蹦床(trampoline)去, 实现了在无需控制流信息的情况下静态重写x86_64的二进制文件. 
  * 传统二进制重写工具的步骤: 
    1. 使用一个反汇编器前端解析二进制文件的机器码指令. 
    2. 恢复控制流信息.
    3. 对插入/删除/替换/重定位后的二进制代码进行转换
    4. 输出修改后二进制的后端. 
  * 实际情况下二进制很难恢复控制流信息, 传统方法仅能针对小且简单的文件 
  * `instruction punning`(指令修补): 一种轻量级的动态插装方法. 
  * 现有的x86_64补丁技术
    1. `Signal Handlers`: 用单字节`int3`指令替换每个patch处的指令. `int3`会触发中断, 信号处理程序接受到该中断进行patch. 但是中断需要内核/用户模式的上下文切换, 性能极差. 
    2. `Jumps`: 用跳转指令代替patch位置的指令, 跳转指令会跳向实现该patch的蹦床. 蹦床执行完转回主程序, 这种方法比中断要快很多. 在x86_64上可以使用`jumpq rel32`来实现, 该指令长度为`5`, `1`个字节是跳转指令的操作码, `4`个字节则是`rel32`. 因此patch位置的指令大于等于`5`个字节时就可以之间进行替换. 而小于`5`个字节的时候就难以适用.
    3. `Instruction Punning`: 找到一个与任何重叠指令共享相同字节表示形式的相对偏移值`rel32`, 然后用此特殊的`rel32`值将补丁指令安全地替换为相对近跳转. 
       * 例如:  `mov %rax,(%rbx) add $32,%rax`
       * original: 48 89 03 48 83 c0 20
       * patched:  e9 xx xx 48 83 c0 20
       * 假设我们需要修补的是这个`3`字节长的`mov`指令. 我们就可以修改前3个字节, 同时利用重叠的`48 83`进行跳转, 也就是`jmpq 0x8348xxxx`, 这样我们就实现了修改3个字节的同时的得到了5字节的跳转指令. 
       * 同样蹦床的位置(`rel32`)也就被限制在了`0x8348xxxx`的范围. 同时`0x8348xxxx`也不一定是有效的地址范围, 如果指向了无效的地址范围, 那么就不能用作蹦床位置. 因此这也就是该技术遇到的关键问题. 
    * 论文的方法: 结合`Jumps`和`Instruction Punning`方法, 如果这两个方法都失败了, 那么就根据策略T1/T2/T3组合进行指令的`padding/punning/eviction`(填充/修改/逐出). 
  * Patch策略:
    * 基于以下指令序列进行解释
    
      ```
      Ins1: mov %rax,(%rbx)  
      Ins2: add $32,%rax 
      Ins3: xor %rax,%rcx
      Ins4: cmpl $77,-4(%rbx)
      ```

    * ![e9patch-tactics.png](assets/e9patch-tactics.png)
    * T1(Padded Jumps): 使用冗余的指令前缀来填充跳转指令. 如图所示, T1(a)的冗余前缀是`48`, T2(a)的冗余前缀是`48 26`. 使用冗余前缀的缺点就是会限制可操控的范围, 比如B2的范围是`0x8348xxxx`, 但T1(a)的范围只有`0xc08348xx`, T1(b)则是一个具体的值了. 
      * T1的适用性取决于补丁指令的长度, 长度越大, 能右移尝试的次数也就越多. 同时也意味着T1不适用于`单字节指令`. 同时右移会受到越多的范围约束. 
    * T2(Successor Eviction): 使用后一个指令(ins2)的pacth冗余来填充跳转指令(ins1). 比如利用T1策略将`ins2`填充为`e9 YY YY YY`, 那么可以再次应用T1策略让`ins1`利用`ins2`的冗余`e9 YY`, 那么可以控制的范围就成了`0xYYe9XXXX`. 而这个策略不仅能提高覆盖的范围, 也能适用于单字节指令(直接覆盖为e9)
    * T3(Neighbour Eviction): 通过短跳转(-128~127)来跳转到附近的可用指令, 到达后结合T1和T2使用得到更大的覆盖范围. 
  * `Reserve Order Patching`: 按照反向顺序修补指令, 比如先补丁Ins2指令, 然后补丁Ins1指令. 

</details>

<details>
<summary>Day19: 对Python代码进行数据流前向切片</summary>

- [x] [romanofski/programslice](https://github.com/romanofski/programslice)
  * 仅实现了前向切片
  * 程序的切片函数入口是`slice_string`. 它接受5个参数, 前3个是用于指定你要跟踪数据流的变量名以及该变量所在位置(行和偏移). 然后给定程序代码片段. 

    ``` python
    node = ast.parse(source, filename)
    visitor = programslice.visitor.LineDependencyVisitor()
    visitor.visit(node)
    graph = visitor.graph
    if graph:
        start = programslice.graph.Edge(varname, currentline, offset)
        result = programslice.graph.Slice(graph)(start)
    return formatter(result, source)()
    ```

  * 分析和遍历是借助模块`ast`来实现的. 通过继承`ast.NodeVisitor`实现`LineDependencyVisitor`类, 并重写了`visit_FunctionDef`和`visit_Name`方法. 
    * 重写`visit_FunctionDef`只是单纯清空了保存的`writes`和`reads`字典. 这是避免函数之间的结果冲突. (也就是还不支持跨函数的分析)
    * `visit_Name`则是关联的重要步骤. 因为通过`ast`我们可以遍历语法树里的节点, 对于数据流分析, 如果仅仅是关注某个变量的数据流向, 那么只需要关注`read`和`write`. 同时表现也就是`ast.Load`和`ast.Store`. 那么在遍历到这样的情况后, 就可以进行关联.
  * 关联后得到`graph`. 然后根据给定的起始变量`varname`和它所在行和偏移, 进行前向切片得到`result`
  * 因为边的关联都在`graph`里关联好了, 所以在指定好变量后, 前向切片也不过是从指定的边开始, 匹配所有相关的边而已. 这里使用了深度优先的方法进行遍历. 

    ``` python
    visited = [edge]
    children = deque(self.graph.get(edge))
    if not children:
        return []

    while children:
        edge = children.popleft()
        if isinstance(edge, Graph) and edge not in visited:
            slice = Slice(edge)
            visited.extend(slice(edge.first))
        elif edge not in visited:
            children.extend(deque(self.graph.get(edge)))
            visited.append(edge)

    return visited
    ```

</details>

## 相关资源

* [CTF Wiki](https://ctf-wiki.github.io/ctf-wiki/): 起初是X-Man夏令营的几位学员, 由[iromise](https://github.com/iromise)和[40huo](https://github.com/40huo)带头编写的CTF知识维基站点. 我早先学习参与CTF竞赛的时候, CTF一直没有一个系统全面的知识索引. [CTF Wiki](https://ctf-wiki.github.io/ctf-wiki/)的出现能很好地帮助初学者们渡过入门的那道坎. 我也有幸主要编写了Wiki的Reverse篇. 
* [漏洞战争:软件漏洞分析精要](https://book.douban.com/subject/26830238/): [riusksk](http://riusksk.me/)写的分析大量漏洞实例的书, 一般建议先学习过[《0day安全:软件漏洞分析技术》](https://book.douban.com/subject/6524076/)后再阅读该书. 我早先阅读过该书的大部分内容, 一般我看漏洞分析的文章都有点跟不太上, 但是看该书的时候作者讲的还是蛮好的. 另外该书是按`漏洞类型`和`CVE实例`划分章节, 所以可以灵活挑选自己需要看的内容. 
* [0day安全:软件漏洞分析技术](https://book.douban.com/subject/6524076/): Windows漏洞分析入门的必看书就不多介绍了. 这本书曾一度抄到千元的价格, 好在[看雪](https://www.kanxue.com/)近年组织重新印刷了几次, 我也是那时候入手的该书, 可以多关注下看雪的活动. 该书的内容很多也很厚实, 入门看的时候可谓痛不欲生, 看不懂的就先跳过到后面, 坚持看下来就能渡过入门的痛苦期了.
* [软件保护及分析技术](https://book.douban.com/subject/26841178/): 该书分为2个部分, 前半部分讲保护和破解的技术, 后半部分造轮子. 前半部分讲的技术分类都蛮多的, 不过大多都是点到即止深度不够, 所以我一般都是看前半部分的当速查和回顾的工具书. 我接下来的目标是该书后半的造轮子部分. 
* [Android安全攻防实战](https://book.douban.com/subject/26437165/): 一本可能适合新手阅读的Android安全书籍, 因为里面涉及的代码比较少分析的难度相对低一些. 这本书更多的是给你一个如果去研究Android安全, 发掘安全问题的角度和思路, 有从开发者的视角做防护也有攻击者的视角去分析. 主要是真不难而且篇幅不多, 我觉得还是蛮适合上手的. 

## 腾讯玄武实验室

### 招聘情报

<details>
<summary>2020/4/8 实习生招募</summary>

> 来自玄武实验室微信公众号当日推送

基本要求: 
1. 在任意系统环境(`Android/Linux/MacOS/iOS/Win`)下有丰富`逆向调试经验`, 并熟悉`安全机制`和`底层架构`.
2. 熟练使用一种`编译型语言`和一种`脚本语言`

加分项:
1. `现实漏洞研究分析经验`, `实际挖掘过漏洞`, `写过利用代码`. 
2. 掌握漏洞研究所需的各种能力, 包括`IDA插件开发`, `Fuzzer开发`, `代码脱壳加密`, `网络协议分析`等.

优劣势分析: 
1. 我有足量时间的`Android/Linux/Win`的逆向调试经验, 对于`Linux/Win`的安全机制和底层架构有一定了解, 不了解`Android`的安全机制和底层架构.
2. 编译型语言(`C/C++`)我的掌握程度一般, 脚本语言(`Python`)掌握良好. 
3. 漏洞研究分析经验是工作的必要内容, IDA插件开发部分, 我曾学习过[IDAPython](https://github.com/Vancir/IDAPython-Scripts)的内容, 对于7.0以上版本还需要了解. `Fuzzer`开发部分是我欠缺的, 我仅详细阅读过`FuzzIL`和`AFL`的源码实现, 并未有实际的开发经验. 有着一定的代码脱壳加密经验, 不过仍需多加练习. 网络协议分析我不擅长也不喜欢, 可以忽略.
</details>

## 关于X-Man夏令营

非常感谢[赛宁网安](http://www.cyberpeace.cn/), [诸葛建伟老师](https://netsec.ccert.edu.cn/chs/people/zhugejw/)和[陈启安教授](https://information.xmu.edu.cn/info/1018/3156.htm)的帮助才让我有幸成为第一期X-Man夏令营的成员. 我也是在X-Man夏令营里认识了[A7um](https://github.com/A7um), [iromise](https://github.com/iromise), [40huo](https://github.com/40huo)等一众大佬. 就我同期的X-Man夏令营学员们, 几乎都投身于国内的安全事业, 如今学员们遍地开花, 也是诸葛老师非常欣慰看见的吧. 

## 关于作者

从初入社会到如今的这半年多时间里, 我找到了生活工作和学习的节奏, 我并没有选择急于去钻研技术, 而是阅读了更多的非技术类书籍, 这教导了我为人处世的经验, 在北京站稳了脚跟, 顺利从刚毕业的懵懂小生过渡到现在略有成熟的青年. 而如今我要展开脚步, 去追求梦想的工作了, 所以我创建了该项目, 既是对自我的激励监督, 也是向分享我的学习历程.

玄武实验室对于国内安全从业人员的吸引力, 就如同谷歌对广大程序员的吸引一般, 我渴望着得到玄武实验室的工作. 而我认识的[A7um](https://github.com/A7um)也在玄武实验室, A7um是我初学安全时仰慕的偶像之一, 我期待着能与玄武实验室里才华横溢的大佬们一起共事研究. 