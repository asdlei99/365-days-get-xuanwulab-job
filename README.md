# 365天获取玄武实验室的工作

## 这是什么? 

这是一份我给自己365天内获取腾讯玄武实验室工作定下的学习进度清单, 用于记录我在这一年时间里每天的学习收获. 

由于已经工作并非学生了, 我将白天的工作定义为自身能力的实践锻炼, 而晚上也就是本清单则注重于知识和理论的学习.

因为知识积累的差异, 该清单并不适用于纯粹的初接触安全者, 但我常认为自己是一个愚笨的人, 所以即便是刚入行的小白, 在补足了一定的基础知识后, 该清单依然具有一定的参考价值. 

> 因为时常有新的点去关注, 所以很多时候学习的内容并不连贯甚至于碎片化, 这也是无可避免的, 有待我填完坑后重新整一份新的清单, 更贴合正常学习的顺序.

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
            | Condition Code | Meaning (for cmp or subs)              | Status of Flags  |
            | -------------- | -------------------------------------- | ---------------- |
            | CS or HS       | Unsigned Higher or Same (or Carry Set) | C==1             |
            | CC or LO       | Unsigned Lower (or Carry Clear)        | C==0             |
            | MI             | Negative (or Minus)                    | N==1             |
            | PL             | Positive (or Plus)                     | N==0             |
            | AL             | Always executed                        | -                |
            | NV             | Never executed                         | -                |
            | VS             | Signed Overflow                        | V==1             |
            | VC             | No signed Overflow                     | V==0             |
            | HI             | Unsigned Higher                        | (C==1) && (Z==0) |
            | LS             | Unsigned Lower or same                 | (C==0)           |  | (Z==0) |
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

<details> <summary>Day20: 详细阅读并总结e9patch的论文内容</summary>

> 项目地址: [e9patch](https://github.com/GJDuck/e9patch): A Powerful Static Binary Rewriter

- [x] [论文总结的PDF](assets/e9patch-summary.pdf)

</details> 

<details> <summary>Day21: 阅读逆向工程参考手册和阅读IDA插件源码</summary>

- [x] [reverse-engineering-reference-manual](https://github.com/yellowbyte/reverse-engineering-reference-manual)
  * 内存中的值存储是小端序, 但是移入寄存器时就是大端序. 
  * 调试寄存器(DR0-7): DR0-3用于存储硬件断点信息, DR4-5保留, DR6是状态寄存器, 其中包含发生调试时间的信息, DR7存储DR0-3的断点条件和长度.
  * CPU尝试执行指令前会检查当前是否触发硬件断点, 如果该地址存储在DR0-3中, 且满足读/写/执行条件, 就会触发`INT1`并暂停进程
  * IDA会显示程序的`本地函数`, `静态链接函数`和`动态链接函数`
  * IDA函数窗口的的一些字段信息: 
    * sagment: 该函数所属的段
    * locals: 局部变量和保存的寄存器长度(字节)
    * arguments: 该函数的参数长度(字节)
    * R: 该函数会返回给调用它的函数
    * F: far function
    * L: 库函数
    * S: 静态函数
    * B: BP based frame. IDA会自动将所有的栈帧指针转变为栈变量
    * T: 该函数包含类型信息
    * =: 栈帧指针是最初的栈指针. 也就是指向栈帧底部.
  * GDB的设置: `set disable-randomization off`和`set disassembly-flavor intel`
  * `apropos <arg>`可以搜索gdb里有关`arg`的命令/文档
  * Microsoft Visual C++编译的程序, this指针保存在ecx, 有时保存在esi, g++编译的程序, this作为函数第一个参数传入.
- [x] [findcrypt-yara](https://github.com/polymorf/findcrypt-yara): 实际上YARA规则来自于另一个开源项目[Yara-Rules](https://github.com/Yara-Rules/rules)里的crypto规则. 插件只是进行了yara匹配把结果显示出来. 
- [x] [ida_yara](https://github.com/alexander-hanel/ida_yara): 利用了yara, 需要手动提供要匹配的字符串或十六进制值, 或者也可以正则, 作者用来搜索IDB里的数据, 但是没有很好的规则只能手动写匹配的话, 适用性有点差. 还不如不要做成IDA插件, 单独利用yara写一个脚本来做通用性的更好些. 
- [x] [ALLirt](https://github.com/push0ebp/ALLirt): libc转换为FLIRT特征是通过flair工具来实现的, 主要是`pelf`和`sigmake`. 另外有一个py库`patoolib`支持多种格式文件的解压还蛮不错. 
  * 创建.pat文件: `./pelf -p64 /usr/lib/x86_64-linux-gnu/libc.a libc.pat`
  * 创建.sig文件: `./sigmake -n <libname> libc.pat libc.sig`
- [x] [IDAFuzzy](https://github.com/Ga-ryo/IDAFuzzy): IDA的模糊搜索插件. 模糊搜索功能由[fuzzywuzzy](https://github.com/seatgeek/fuzzywuzzy)库实现, 这个库的使用也很简单, 可以进行字符串之间的模糊匹配评分, 也可以根据一个字符串从一堆字符串中选出相似的结果.

</details> 

<details> <summary>Day22: 学习熊英飞老师的软件分析技术课程</summary>

> 熊老师的Software Analysis课程主页: [传送门](https://xiongyingfei.github.io/SA/2019/main.htm#info)

- [x] [课程介绍](https://xiongyingfei.github.io/SA/2019/01_intro.pdf):
  * 哥德尔不完备定理: 对任意能表示自然数的系统, 一定有定理不能被证明
  * 主流程序语言的语法+语义 = 能表示自然数的形式系统
  * 停机问题, 内存泄露判定问题, 实质上也是不可判定问题, 也就是不能针对该问题的每一个实例都给出是/否的答案, 也就是说, 计算机没有能力去完全判断一段代码的好坏. 
  * 莱斯定理: 将程序视作一个从输入到输出的函数, 关于该函数的任何`非平凡属性`, 都不存在检查该属性的通用算法. 
    * 平凡属性: 要么对全体程序都为真, 要么都为假的属性
    * 非平凡属性: 不是平凡的所有属性(可以理解为存在差异性)
  * 检查停机问题的算法:
    * 当前系统的状态为内存和寄存器中所有bit的值
    * 给定任意状态, 系统的下一状态是确定的
    * 令系统所有可能的状态为节点, 状态之间的转换作为有向边. 形成一个有向图(有限状态自动机)
    * 如果`从任意初始状态出发的路径都无环`, 那么系统一定停机, 否则可能死机.
    * 因为状态数量有穷, 所以该算法一定终止. 
  * 近似求解判定, 除开回答"是"和"否", 还可以表示一个模糊的判断"不知道". 
    * 上近似: 只输出"否"和"不知道", 因为这里作为下的"否"是精确的, 所以是上近似
    * 下近似: 只输出"是"和"不知道", 同样, 这里作为上的"是"是精确的, 所以是下近似
    * 好的结果当然是尽量回答精确的"是"和"否", 少回答模糊的"不知道"
  * 假设正确答案是集合S:
    * must分析: 返回集合总是S的子集
    * may分析: 返回集合总是S的超集
    * 更全面的分析: 返回S的子集(must), 超集(may), 不相交集(never)
  * 求近似解的另一种方法`搜索`(上一个方法是`抽象`): 穷举所有的组合来回答是或否, 如果超时则认为"不知道"
  * 基于抽象解释的程序分析: `数据流分析`, `过程间分析`, `指针分析`, `抽象解释`, `抽象解释的自动化`.
  * 基于约束求解的程序分析: `SAT`, `SMT`, `霍尔逻辑`, `符号执行`
  * 参考资料: `龙书`, `Lecture notes on static analysis`, `https://cs.au.dk/~amoeller/spa/`, `Principle of Program Analysis`, `Decision Procedures An Algorithmic Point of View`

</details> 

<details> <summary>Day23: 学习高级二进制代码反混淆资料</summary>

- [x] [Advanced Binary Deobfuscation](https://github.com/malrev/ABD):
  * 定义: 混淆就是将程序P转换成更难提取信息的程序P'
  * 混淆的阶段: 
    1. 编译器前端词法分析前的`preprocessor macro source code analysis`阶段进行. 这里我理解为混淆变量名这种的技术
    2. 后端优化时的`inline assembly obfuscation pass`进行. 这里我理解为代码膨胀插入花指令的阶段. 
    3. 后端生成代码后的`packing binary rewriting`阶段进行. 这里我理解为加壳
  * 从`A Tutorial on Software Obfuscation`里可以得知有分为31种已知混淆技术. 
  * 混淆工具: 商业有`Themida`, `Code Virtualizer`, `VMProtect`, `Enigma`, `Epona`等. 学术界有`Tigress`和`O-LLVM`. 
  * 恶意软件会在早期的传播过程中使用混淆, 例如`macro/script/dropper/downloader/beacon`. 在后阶段的`implant/agent/rookit`使用混淆. 
  * 混淆技术的通用手法:
    * 做无用功: 插入垃圾指令或dead code. 用于遮掩和干扰
    * 改变语法: 替换等价指令, 编码文本和算术操作
    * 改变语义: `Opaque Predicate`混沌不透明谓词? 控制流平坦化, 代码虚拟化
  * 混淆技术:
    - [x] Garbage/Dead Code Insertion: 插入不会影响预期结果的指令, 通常会结合其他混淆技术
    - [x] Instruction Substitution: 将指令替换成等价的, 更复杂的指令
    - [x] Encode Literals: 将文本信息(常量, 字符串等))替换成更复杂的表达. 比如将"helloworld"拆分成单个字母串起来. 
    - [x] Encode Arithmetic/Mixed Boolean Arithmetic: 将算术操作/布尔逻辑替换成更复杂的表达. 比如a+b, 转换成a-(-b)
    - [x] Opaque Predicate: 对于没有分支的地方, 加一个永远也不会触发的分支. 可以通过插入一个确定性的操作实现. 比如说`cmp eax, 0xfffffff`, 强行增加一个分支出来. (或者利用其他的恒等式/恒不等式)
    - [x] Virtualization Obfuscation: 将代码替换为虚拟机的字节码, 由虚拟机解释执行. 
    - [x] Control Flow Flattening: 利用switch语句, 让平坦化的每一个基本块都有一个索引, 根据索引跳到下一个基本块, 执行基本块时更新索引, 这样就能使得跳到switch同级的不同基本块去.
  * 解混淆技术:
    * 途径: 
      * 简化: 将代码转换成可读的形式
      * 消除: 移除冗余代码
      * 动态分析: 避免直接阅读混淆代码
    * 技术栈: `数据流分析`, `符号执行`, `等价性检查`, `抽象解释`, `程序生成`, `污点分析`
  * 解混淆针对混淆技术各个阶段的策略:
    * 做无用功 <- 数据流分析(存活性分析)
    * 改变语法 <- 数据流分析(可达性分析)
    * 改变语义 <- 符号执行, 等价性检查, VMHunt, 程序生成, 图特征匹配.
  * 程序分析的工具: IDA, radare2, Binary Ninja, angr, BINSEC, Triton, Miasm, McSema等
  * 程序分析前后端:

  ![abd-binary-analysis-architecture.png](assets/abd-binary-analysis-architecture.png)

  * 中间表示(IR): 
    * IR的目的是为了方便进行二进制代码的分析
    * IR能帮助处理多种架构的代码(平台无关).
    * IR通常是SSA格式: 每个变量仅分配一次, 在使用前定义. 这个属性能帮助优化和转换. (能帮助消除歧义)
    * IR也有难以建模的地方, 因此不能完全等价于原来的代码, 只能做到近似. 
  - [x] 数据流分析(我要回去看下南大李老师的视频解说)
    - [x] 可达性分析:
      * 前向数据流分析
      * 分析程序到达某个点P时, 变量x的值于何处被定义
      * 应用: `Constant propagation/folding`, `Transform expressions`
    - [x] 存活性分析
      * 后向数据流分析
      * 分析从p起始的边到x时, 在p点x的值是否可用. 
      * 应用: 消除死代码
    - [x] 限制
      * 保守方法: 保留了程序语义, 假定传递程序的整个路径
      * 流敏感, 路径不敏感: 会注重指令的顺序, 不注重条件分支
      * 如何干扰数据流分析? 
        * 插入不透明谓词
        * 因为数据流分析不关注哪条路径被实际执行了,

</details> 


<details> <summary>Day24: 阅读混淆技术论文综述部分内容</summary> 

- [x] [A Tutorial on Software Obfuscation](https://mediatum.ub.tum.de/doc/1367533/file.pdf)
  * 混淆工具输入程序输出功能等效但是更难理解和分析的另一个程序. 一些经典的编译器优化选项也被认为是混淆的一种, 因为它为了使代码更高效而将开发人员易于理解的代码替换成其他代码. 
  - [x] Classification of Code Obfuscation Transformations:
    - [x] Abstraction Level of Transformations:
      * 常用的分类维度就是混淆转换所发生/抽象的级别, 比如源代码层, 中间表示层, 二进制机器代码级别. 
      * 这样的分类的目的在于可用性, 比如JS跟关心源代码混淆, 而C跟关心二进制级别混淆. 
      * 存在某些混淆转换能对多个抽象级别都产生影响
    - [x] Unit of Transformations:
      * 考虑混淆转换的粒度, 有以下几种:
        * 指令级: 应用于单个指令或指令序列. 
        * 基本块
        * 循环结构: 替换掉开发者熟悉的循环结构
        * 函数级: 影响函数的特定指令和基本块, 此外还可能影响函数对应的堆和栈
        * 系统级: 针对操作系统或运行时环境. 影响程序与之交互的方式.
      * 开发者可以根据他们要保护的资产来选择相应的粒度, 比如循环级别转换不适用于隐藏数据, 但适合隐藏算法.
    - [x] Dynamics of Transformations:
      * 将混淆转换静态/动态地应用于程序或其数据上, 静态转换发生在`实现/编译/连接/安装/更新`的过程, 也即程序及其数据并不会在执行时发送变化. 但程序或其数据可以在`加载/执行`期间发生变化, 比如程序可以在加载时进行解码
    - [x] Target of Transformations
      * 分类的零一常见维度就是转换的目标. 最初可分为: `布局/数据/控制/预防`性转换, 但后面也有人提出其他的分类: `抽象/数据/控制/动态`转换. 因此我们可以大致分为以下两类:
        * 数据转换: 修改程序中硬编码的常量值(比如数字/字符串/键等)的`表示形式和位置`, 以及变量的`内存值`
        * 代码转换: 转换`高级抽象`形式(比如数据结构, 变量名, 缩进等)以及`算法`和`控制流. 
  - [x] Classification of MATE Attacks
    - [x] Attack Type Dimension
      * 根据Collberg的理论, 攻击者对以下四种信息的恢复感兴趣:
        * 源代码的原始或简化版本: 知识产权盗窃
        * 静态嵌入或动态生成的数据: 比如解密密钥, 硬编码的密码, IP地址等
        * 用于混淆的转换序列或混淆工具(元数据): 杀毒引擎可以根据这些数据检测可疑文件
        * 特定功能代码的位置: 攻击者可以复用这块功能代码而不必了解其实现方式(比如解密数据模块)
      * 将攻击类型分为三类: 1. 代码理解 2. 数据项恢复 3. 位置信息恢复
    - [x] Dynamics Dimension
      * 动态分析会运行程序, 并在执行过程中记录已执行的指令, 函数调用以及内存状态
      * 与静态分析相反, 动态分析通常时不完整的, 即它不能探索和推理程序的所有可能的执行状态.
    - [x] Interpretation Dimension
      * 指是将程序代码或者由代码而来的分析结果(比如静态反汇编, 动态跟踪指令序列)视为文本还是根据其语义(操作的语义)进行解释. 
      * 语法攻击: 将源代码或分析结果视为一串字符串, 比如通过模式进行匹配, 或将代码视作字符串序列扔给机器学习进行模式识别.
      * 语义攻击: 根据某些语义来解释代码(如指称语义, 操作语义等), 比如`抽象解释`使用`指称语义`, `模糊测试`使用`操作语义`
    - [x] Alteration Dimension
      * 是指自动化攻击是否会修改代码. 
      * 被动攻击: 不会对程序代码或数据进行任何更改, 比如从程序中提取密钥和密码不会更改任何代码
      * 主动攻击: 会更改程序的代码或数据, 例如删除数据/代码的完整性检查相关代码. 

</details>

<details> <summary>Day25: 了解各类混淆转换技术以及对应对抗方法</summary>

- [x] [A Tutorial on Software Obfuscation](https://mediatum.ub.tum.de/doc/1367533/file.pdf)
  - [x] Constant Data Transformations
    - [x] Opaque predicates
      * 不透明谓词其实就是一个结果固定不变的表达式, 但攻击者很难静态推断这个结果. 
      * 可以通过在循环条件中添加不透明谓词, 虽然不会影响循环条件, 但是会让攻击者更难理解循环何时终止.
      * 可以通过难以静态求解的数学公式来创建不透明谓词, 也可以用其他难以静态计算的问题, 比如`别名`来构建.
      * 别名的状态是难以确定的, 比如就是`指针别名分析`问题, 难以确定在给定的执行点中, 哪些符号是某个具体内存位置的别名. 
      * 因此可以利用别名的不确定性来构建`链表`作为不透明谓词: 通过构造链表操作, 对于混淆器而言, 它是知道链表指针指向的值`*q1 > *q2`的, 但是对于攻击者静态分析而言, 难以去分析链表操作去得知这个结果. 
      * 一些研究提出的对不透明谓词的对抗方法: `基于抽象解释的位置和数据恢复`, `基于符号指向的数据恢复和代码理解策略`, `通过识别已知的不透明谓词来理解和识别其他程序`
    - [x] Convert static data to procedural data (a.k.a. Encode Literals)
      * 混淆硬编码常量的简单方法就是将其转换为`运行时生成常量的函数(过程)`, 这也就意味着这个函数(过程)是可逆的. 
      * 但是编译器优化过程可能会将这些过程解开恢复为原始的值, 因此我们可以通过`不透明表达式`来做替换.
      * `不透明表达式`跟`不透明谓词`类似, 只是`不透明谓词`的结果是一个`布尔值`, 而`不透明表达式`的结果是`非布尔值`. `不透明表达式`通过依赖外部数据来构造值, 其在程序执行期间的值是固定的, 比如`cos2(x) + sin2(x) === 1`, 而这样也能避免编译器优化将其摊解开. 也可以做到`"A"+"B"+"C" = "ABC"`这样的将单字节拼接成字符串的方法. 
      * 对抗方法: `两次语义攻击`, `基于符号执行和模式识别的攻击`(也可以对抗不透明谓词)
    - [x] Mixed Boolean-Arithmetic
      * 简单来说, 就是通过`1+(2*3)+4-5-6`的结果恒定为`0`这样的手法来隐藏固定值`0`, 只是作者使用了`布尔表达式`来完成这样的运算(因为简单的算术运算肯定会被编译器优化掉). 通过这样的混合布尔运算来动态地计算硬编码的原始值. 
      * 对抗方法: 提出了Arybo的静态分析工具, 能简化MBA表达式, 该攻击旨在了解代码和恢复数据, 并使用代码语义来实现此目标. 
    - [x] White-box cryptography
      * 白盒加密的目标: 无需硬件密钥或可信实体, 而是在软件中安全地存储密钥.
      * 白盒密码技术并非是将密钥与加密逻辑分开存储, 而是将密钥嵌入密码逻辑内部. 比如AES可以将密钥嵌入T-box中, 然后再每个加密回合中与T-box相乘, 但这样容易遭受`密钥提取攻击`. 因此`WB-AES`使用更复杂的技术来防止`密钥提取攻击`, 比如`宽线性编码`, `对密码方程式做扰动`和`对偶密码`
    - [x] One-way transformations
      * 通俗的来说, 就是对于一些无需在运行时计算, 只需要判断是否相等的情况下, 可以用单向转换的方式来验证. 比如验证密码, 可以先将正确的密码进行sha256哈希后, 存储到代码里. 然后用户验证的时候重新算一次sha256跟正确的密码的哈希值进行比较, 就可以知道用户输入是否正确. 这样的单向转换就迫使攻击者必须猜测正确的密码才能完成验证, 或者去`绕过相等性检查代码`. 所以这里就需要高度保护和检查相等性代码, 以避免攻击者对其进行篡改. (比如`==`变为`!=`)
      * 对抗方法: 提出了一些方法对哈希函数进行碰撞. 
  - [x] Variable Data Transformations
    - [x] Split variables
      * 思路: 用多个变量来代替一个变量. 比如1个32bits的int变量可以分为4个8bits的byte变量表示.
      * 类似于将静态数据转换成函数/过程生成数据. 但是这里的变量可以适用于任何值而非单纯的常量. 比如你可以把所有的int都用4个bytes表示.
      * 不过由此而带来的影响就是, 所有的算术运算我们都需要`重载运算符`来完成, 因为毕竟你的数据组织格式发生变化了. 
      * 对抗方法: 提出了一种基于所谓的`temporal reuse intervals(时间重用间隔)`的动态跟踪分析技术的数据恢复攻击, 时间重用间隔能`指示内存的使用模式`, 并且也适用于对抗接下来介绍的`merge variables`方法
    - [x] Merge variables
      * 思路: 与将`split variables`不同, 它的思路是将多个变量合并为一个变量, 只要变量合并的范围在精度范围内即可(不丢失精度). 例如将4个8bits变量合并为1个32bits变量. 
      * 同样也要重载运算符, 但是这里要更加小心地去设计算术运算, 避免对无关的变量造成影响. 并且需要多合并的`所有变量`都涉及一套运算. 
      * 对抗方法: 上述的能指示内存使用模式的攻击方法, 当然人工动静态分析也是能成功逆向出来的. 
    - [x] Restructure arrays
      * 思路: 与变量类似, 数组可以拆分/合并, 除此外还能`折叠(增加维数)/展开(减少维数)`
      * 数组的`折叠/展开`会迫使攻击者了解代码逻辑才能恢复这种抽象的信息. 
      * 对抗方法: 提出了一种代码理解攻击, 该攻击基于符号执行产生的`执行轨迹`之上的`访问模式`进行模式识别, 结合了动静态技术, 以便从混淆代码中恢复数据结构. 该攻击不仅能针对数组重组, 还能针对之后介绍的`loop transformations`
    - [x] Reorder variables
      * 思路: 通过`转换或替换`变量, 来改变代码中变量的`名称或位置`. 比如将汇编代码里的`eax`寄存器更换成`edx`寄存器来做一些操作(比如临时存放变量用)但是不影响结果. 
      * 这样的转换成本比较低并且攻击者很难去识别这种模式. 这样的转换能减少ROP利用可用的gadget(研究实现原型减少了40%).
      *  对抗方法: 提出一种自动化攻击, 能够执行数据恢复, 以提取恶意软件字符长签名, 并能够破解这种对重排序变量的转换. 
    - [x] Dataflow Flattening
      * 是`Reorder variables`的改进版, 通过内存管理单元(MMU)定期对堆中存储的数据进行重新排序, 并使程序的功能不变. 
      * 实现思路:
        1. MMU为给定变量在堆上分配性的内存区域
        2. MMU将变量的值复制到新的内存区域
        3. MMU更新变量的所有指针从旧存储区指向到新存储区
        4. 最后MMU重新分配旧的内存区域(给其他变量)
      * 除了对堆上数据进行重排外, 数据流展品还建议将`所有局部变量`从栈转移到堆, 这样能加扰指针以隐藏返回给程序的不同指针的关系. 不过这种转换的执行开销也很高.
      * 对抗方法: 暂无
    - [x] Randomized stack frames
      * 思路: 为每个新分配的`栈帧`分配`栈上的随机位置`. 为此, 它会从`function prologue(函数序言, 也就是函数汇编入口处的一系列修改栈指针的指令)`中的`栈指针减去一个随机值`, 然后在`函数结语`添加回这个随机值(保持堆栈平衡).
      * 对抗方法: 提出了一种`buffer overread(不是bof)`的数据恢复攻击来绕过随机栈帧保护. 
    - [x] Data space randomization(DSR)
      * 思路: 使用随机生成的掩码(mask)对内存中的数据进行加密(比如异或xor). 掩码不需要设置为固定值, 而是可以在运行时动态生成并加密数据值. 
        1. 每当程序需要读取数据时, 首先用正确的掩码进行解密. 
        2. 在对解密数据值进行授权修改后, 根据实现方式, 使用相同/不同的掩码对结果进行重新加密. 
      * 该技术受`PointGuard`(它能对代码指针进行加密)的启发, DSR能防止从内存中提取或修改数据.
      * DSR的实现难题在于: 不同的指针可能指向`同一个加密的内存值`, 因此它们必须使用`相同的掩码`来解密数据. 我们可以用指针别名分析来部分解决问题, 但是别名分析并非完全准确, 因此只能近似的解决该问题.
      * DSR引入了平均15%的运行时开销, 并可以防止缓冲区和堆溢出攻击.
      * 对抗方法: 上述提出的`buffer overread`的攻击方法也能用于绕过DSR
  - [x] Code Logic Transformations
    - [x] Instruction reordering
      * 思路: 这次重排的目标是`指令序列`, 重排后不会改变原始程序的执行. 不过它的混淆力度并不强, 不会大大增加代码理解的难度. 
      * 重排所针对的指令序列也是并行处理优化的对象, 因为它们可以有不同的执行线程独立执行, 不会带来竞争条件的问题. 而且这种重排的成本也很低. 
      * 研究者在二进制基本块级别进行重排, 将ROP利用gadget数量减少了30%以上, 而与指令级重排相比其弹性降低的幅度也较小.
      * 对抗方法: 提出了一种静态代码理解攻击, 以检测APK恶意重打包. 该攻击使用代码语义来构建每个app的`view graph`, 将其与其他应用程序进行比较以确定它们是否是同一app的重打包版本. 研究者称该方法可以对抗多种混淆转换: `merging functions, opaque predicates, inserting dead code, removing functions, function argument randomization and converting static data to procedural.`
    - [x] Instruction substitution
      * 思路: 基于以下事实: 某些编程语言及不同给定ISA中, 存在多个(顺序)等效指令. 这意味着可以用一条等效指令替换另一条指令(序列)而不会改变程序的语义行为, 但这能导致不同的二进制表示形式. 比如swap交换变量这个操作, 可以用多个mov指令来完成, 也可以直接用push/pop来完成. 
      * 该转换的性能开销适中, 但是由于可用来转换的指令序列数量有限, 因此对抗攻击的防御力很低. 
      * 研究者在基础块级别使用了该转换, 发现其减少了不足20%的gadget数量. 此外, `使用不常见的指令`回降低防御能力, 也就是回向攻击者指示替换所发生的位置. 
      * 为了提高这种转换的隐匿能力, 研究者提出了`instruction set limitation`技术, 根据程序中指令类型的统计分布来挑选候选替换指令. 另一研究者也提出类似技术, 旨在将shellcode编码为英语文本来提高shellcode的隐匿性.
      * 对抗方法: 上述介绍到的对抗`不透明谓词`的代码理解和数据恢复攻击能应用于绕过该转换.
    - [x] Encode Arithmetic
      * 思路: 它是指令替换的一种变体. 将布尔/算术表达式用等价的另一种复杂的布尔/算术表达式做替换.
      * 同样, 能使用的布尔/算术等价表达数量有限. 
      * 对抗方法: 通过模式匹配识别混合布尔算术(MBA)表达式, 并为每个表达式编写一个逆变换.
    - [x] Garbage insertion
      * 思路: 插入任意指令序列, 这些指令序列与原始程序的`数据流无关`, 并且`不影响`其输入输出(I/O)行为(功能)
      * 实际上能插入的可能序列是无限的, 但是性能开销与插入的指令数量成比例增长.
      * 垃圾代码只能在执行编译器优化后插入, 因为可以通过污点分析识别并消除垃圾代码.
      * 对抗方法: 提出了基于污点分析的通用攻击方法, 该技术的仅受限于实际运行时约束(例如时间开销和内存开销)的限制, 因为与死代码不会执行不同, 垃圾代码总是会执行的.
    - [x] Insert dead code
      * 思路: 修改程序的控制流, 添加一个无效(决不会使用)的分支. 不透明谓词可以帮助添加无效分支. 
      * 对抗方法: 符号执行方法, 编译器领域也有许多死代码删除的优化方法
    - [x] Adding and removing function calls
      * 思路: 可以应用于任何的`转换单元`, 比如指令,IR, 基本块, 方法就是将转换单元进行`封装/解构`. 比如`c=a+b+1`就可以转变为`c = add(a,b)+1`, 反之亦然. 从效果上看就是增加函数调用的开销很啰嗦.
      * 研究者进一步扩展了该转换, 将现有的`系统调用`替换为`等效的系统调用`, 研究者将这种转换称之为`行为混淆`, 因为它隐藏了目前恶意软件行为分析引擎所需要分析的`系统调用轨迹`
      * 对抗方法: 基于机器学习的恶意软件检测方法, 因为机器学习会将函数调用轨迹视为字节序列作为输入. 
    - [x] Loop transformations 
      * 思路: 多层`嵌套/解构`循环, 能增加代码的复杂程度, 也被视作混淆的一种办法. 
      * 对抗方法: 上述介绍的针对数组重组转换的攻击方法.
    - [x] Adding and removing jumps
      * 思路: 通过`添加伪造跳转/删除已有跳转`来更改程序控制流. 可以理解为代码hook. 实践中为了增加复杂度常用的时添加跳转的方式. 
      * 该技术的转换空间受其应用程序长度的限制, 成本随着插入的指令数量而增加.
      * 可以通过使用`数据混淆技术(例如不透明表达式)`或`将静态数据转换为过程数据`来进一步`混淆跳转的目标地址`, 以增加抵御能力.
      * 对抗方法: 提出了增强CFG进行动态污点分析, 这样无需逐个移除跳转指令.
    - [x] Program encoding
      * 思路: 程序事先对多个指令进行了编码, 而在运行时动态地对指令序列节码. 
      * 抵御能力取决于编码的算法, 例如无需密钥就能进行的压缩算法, 或需要找到密钥的解密算法. 但成本可能较高, 因为在执行代码前必须对代码解码. 
      * 而且抵御能力与成本之间存在权衡, 具体取决于编码的粒度. 如果时所有指令都在执行时才解码, 那么攻击者无法通过内存dump来得到解码后的代码. 而如果以程序级进行编解码, 那么攻击者时可以等你解码完之后dump内存来获取代码的. 
      * 此外该技术无法很好地抵御动态分析, 因为执行过程中代码在内存中解码, 攻击者可以在内存中之间读取/修改代码.
      *  对抗方法: 研究者提出被动句法攻击, 以混淆后的恶意程序中字节值的位置和分布提取特征. 另一研究者提出基于污点分析的动态语义攻击, 以确定代码中的完整性检查代码的位置. 
    - [x] Self-modifying code
      * 思路: 在程序执行期间添加/修改/删除程序的指令. 因此它能给静态分析带来很大的难度.
      * 实现方法1: 用伪造指令来代替实际指令, 执行到伪造指令时, 再用实际指令替换回去执行, 实际指令执行完后, 再用伪造指令替换回去. 这种转换要求对改动指令的`所有执行路径`都进行合理的分析.
      * 实现方法2: 在函数级别上, 将函数用统一的`函数模板`做替换来实现自修改. 这要求函数模板里的数据结构要能兼容所有被替换的函数. 所有被替换的函数应用`函数模板`时会生成一个`编辑脚本`, 我们可以理解为函数的`diff`文件, 以便根据函数模板重建对应的函数.
      * 对抗方法: SMC可以有效地对抗那些会破坏代码完整性的动态分析(比如动态patch). 但研究表明, SMC会对加密密钥的机密性产生负面影响, 因为使用不同的密钥对同一代码进行加密会泄露代码的信息, 这类似于两个时间片. 因此SMC不应当保护解码函数. 研究者应用了一种基于抽象解释的攻击来为变形的恶意软件样本生成签名. 
    - [x] Virtualization obfuscation
      * 思路: 通过对指令进行编码, 并使用额外的解释引擎(称为模拟器或仿真器)来解码指令并在底层平台上运行指令. 
      * 该模拟器可以在另一个模拟器之上运行, 形成多层嵌套. 攻击者必须先了解这个定制的模拟器的解释逻辑才能继续分析. 
      * 虚拟化和程序编码的最大不同就在于, 解码期间无需将任何代码写入存储位置(解码时即运行). 但成本考量跟程序编码一样. 
      * 虚拟化的实现方法:
        1. 将`变量/函数参数/常量`映射到`data数组`里的条目, `data数组`代表解释器的内存. 
        2. 将函数中的`所有语句`映射为解释器的指令集(解释器所使用的bytecode).
        3. 将编码后的bytecodes存储到`code数组`中
        4. 创建解释器, 执行`code数组`中的字节码作为指令, 使用`data数组`的内容作为内存. 解释器解释执行的输入输出行为必须于源程序保持一致(要等效)
        5. 解释器在一个`while(1)`循环内解释执行代码. 其中包含一个`switch`语句, 其每一个`case`都是一个`opcode handler`来处理. 解释器要处理的`当前指令`由解释器的计数器(`vpc`)表示, `vpc`就是`code数组`的索引, 用于指示相应的指令. 每次进入`opcode handler`完成指令对应操作后会更新`vpc`的值用于指向下一条指令. 
      * 可以在虚拟化的基础上, 可以结合各种代码混淆的转换. 有研究者提出`随机化bytecode指令在code数组中的布局以及这些指令的格式`, 另一研究者提出使用`不透明表达式对vpc的值进行编码, 将解释器调度方法从switch语句更改为查找表的方式`等.
      * 攻击方法: 提出了一种基于抽象解释的静态语义攻击和一种称为`vpc lifting`的技术, 目的是`在任意代码位置自动地恢复内存值`. 另一研究者提出一种手动的静态方法, 以`了解字节码和解释器的opcode handler之间的映射`. 另一攻击者提出了一种动态的句法攻击, 能够`删除解释器的大部分代码, 并恢复程序的原始逻辑`
    - [x] Control flow flattening(CFF)
      * 思路: 将函数内的所有基本块折叠为`平坦的CFG`, 从而隐藏了程序的原始控制流. 
      * 与虚拟化类似, 同样是switch结构, 但不同的是程序的控制流会在各个`case`分支上做跳转. 
      * 而要想恢复CFF平坦化的程序的原始控制流, 就必须简化switch语句里各个case为正确的顺序. 
      * 对抗方法: 提出了结合动静态分析的方法, 能从CFF混淆的程序中准确地恢复原始控制流.
    - [x] Branch functions
      * 思路: 通过对`所谓分支函数的调用`, 从静态反汇编算法中隐藏`函数调用的控制流/有条件跳转/无条件跳转`. 分支函数就是一个根据给定参数, 跳转到对应的分支目标位置的函数(比如指令为无条件跳转`jmp L1`, 那么参数为`L1`, 就会跳向`L1`所在的地址偏移), 也就是将`jmp L1`换成`push L1; call branch_function` (这里对于有条件跳转, 应该还有函数返回地址的处理)
      * 同样能达到平坦化的效果, 只是平坦的对象从switch变为了分支函数(branch function)
      * 对抗方法: 提出静态语义方法来绕过分支函数, 以便在很大程度上分解使用该转换混淆的代码.
  - [x] Code Abstraction Transformations
    - [x] Merging and splitting functions
      * 思路: 类似于`合并/拆分`变量, 这里以函数为单位进行合并/拆分
      * 对抗方法: 提出一种静态语义攻击方法来针对`函数合并`混淆. 其会检测属于不同函数的代码行位置并将其提取到单独的函数中去.
    - [x] Remove comments and change formatting
      * 思路: 删除所有`注释/空格/制表符/换行符`. 仅适用于源代码交付的程序(比如Javascript, HTML等)
      * 对抗方法: 原始的格式和注释无法恢复, 但是可以很轻松地恢复对齐格式. 研究者基于对大型代码库的概率学习, 提出了针对此的代码理解攻击, 并设计了`DeGuard`应用于android程序.
    - [x] Scrambling identifier names
      * 思路: 将所有符号名称(`变量/常量/函数/类`等)替换为`随机字符串`. 这是一种单向转换, 因为符号的名称无法由解混淆器恢复. 攻击者被迫从语义的角度理解符号的具体含义. 相比删除注释的方式, 该混淆效果更佳. 
      * 对抗方法:  基于机器学习的攻击方法, 能够高精度地恢复有意义的标识符名称
    - [x] Removing library calls and programming idioms
      * 思路: 在可能的情况下, 使用自己的实现替换对外部库的依赖. 这样能避免攻击者通过检查对外部库的调用来推断程序的运行行为. 
      * 这种转换比静态链接更强大, 因为静态链接时将库代码复制到程序文件中, 而这可以通过模式匹配的方式轻松地逆向出来. 
      * 对抗方法: 上述针对删除注释和标识符的, 机器学习方法可以对抗该转换.
    - [x] Modify inheritance relations
      * 一些编程语言(比如java)会以某些中间格式存在(字节码文件), 这些中间格式最终会编译为本地代码, 其包含有用的面向对象的编程抽象. 因此很有必要去破坏中间格式里`类/结构/关系(如聚合,继承等)`所提供的抽象信息. 
      * 实现思路: 提出`错误重构`的方法, 将没有共同行为的类都整合进同一个父类里. 有研究者进一步扩展了开方法, 提出了`类层次结构平坦化`的方法, 创建了一个`包含所有类的所有方法的通用接口`, 所有类都实现此公共接口但彼此间没有任何关系. 这样能有效地破坏类的层次结构, 并迫使攻击者分析代码.
      * 对抗方法: 暂无
    - [x] Function argument randomization
      * 思路: 随机化一个方法的`形参顺序`并`插入伪造参数`. 该技术在`Tigress`中得到了应用.
      * 该转换的目的是在大量不同的实例中`隐藏通用函数签名`
      * 对于不提供外部接口的程序, 能很好地应用该转换. 但是对于提供外部接口的库来说, 这样会更改`库的接口`, 并且使用该库的所有对应程序也必须进行更新. 
      * 该转换的抵御能力和成本都很低, 但是可以通过结合`编码算术操作`的转换, 从而使得函数内部的计算依赖于随机添加的自变量, 以此来提高抵御能力. 
      * 对抗方法: 提出的一种静态代码理解攻击能绕过该转换.

  ![overview-of-the-classification-of-obfuscation.png](assets/overview-of-the-classification-of-obfuscation.png)

</details>

<details> <summary>Day26: 阅读二进制代码复用检测论文</summary>

- [x] [BinSequence: Fast, Accurate and Scalable Binary Code Reuse Detection](https://users.encs.concordia.ca/~youssef/Publications/Papers/AsiaCCS2017.pdf)
  * 摘要: 提出了一种`模糊匹配`的方法来比较两个函数. 首先在基本块级别和指向路径级别, 利用最长公共子序列来获取基本块之间的初始映射, 然后使用`领域探索`来对映射做进一步扩展. 在大型数据集上应用`Min-hasing`进行了有效的过滤处理. 基于此方法实现了`BinSequence`工具原型, 实验结果表明该工具高效且准确度超过90%
  * 代码复用检测的应用: 帮助加快逆向, 检查复用带来的安全漏洞, 二进制diff, 软件抄袭检测.
  * 论文贡献
    1. 提出了一种模糊匹配算法用于比较汇编函数. 为了解决编译器带来的差异, 该模糊匹配算法可以在多个级别上运行(指令级别, 基本块级别, 结构体级别)
    2. 应对大数据集, 设计实现了一种有效的过滤处理, 以修剪搜索空间. 
    3. 设计实现了一个原型, 并介绍了相关应用.
  * 论文通过比较两个函数的CFG来评估相似性. 
  * BinSequence框架:
    * 首先将一些有趣的二进制文件(例如分析过的malware或可能会被复用的开源项目)进行反汇编. 输出就是函数的集合.
    * 随后, 将所有函数进行`归一化`, 将其保存在存储库里. 
    * 给定一个待分析的`目标函数`, 然后从存储库中经历两次过滤(因为大多数函数是没有比较的必要的)得到`候选集`. 第一次过滤基于`基本块的数量`, 第二次过滤基于`从各个函数中提取出的特征相似性`. 
    * 然后将`目标函数`与`候选集`中的每个函数进行比较. 比较包括三个阶段:
      1. 首先, 生成`目标函数`的`最长路径`
      2. 然后, 探索`候选集`中的`参考函数`, 以找到`对应的匹配路径`, 也就是基本块之间的`初始映射`
      3. 通过`目标函数`和`参考函数`的`领域探索`来`增强映射`, 输出映射以及这两个函数的`相似度分数`. 对候选集的每个函数都完成该操作后, 基于相似度分数进行排名.
  * 反汇编和归一化:
    * 论文使用IDA Pro作为前端进行代码分析并为每个函数生成CFG. 因为生成汇编代码时, 编译器关于`助记符/寄存器/内存分配`方面有多种选择, 因此需要对基本块中的`每个汇编指令`进行归一化.
    * 大多数体系结构, 汇编指令由助记符和最多3个操作数组成, 因此在归一化时, 保持助记符不变, 仅规范操作数.
    * 操作数分为三类:`寄存器/内存引用/立即数`. `立即数`分为两类: `内存偏移/常量`. 要区分立即数的原因在于地址会随着汇编代码的布局变化而变化, 常量则不会. 这里的常量仅考虑其文本值, 不将字符串作为常量考虑, 因为文件的版本变化是会经常改动字符串的, 并且也可以通过改变字符串来规避复用检查. 而常数值则很少会被编译器优化掉, 更能直接地反映函数关系. 
  * 指令比较:
    * 指令归一化后, 比较函数的助记符(2), 操作数(1), 常量文本值(3)等, 不同的匹配成功给予不同的分数.
    * 指令归一化能更好地减少寄存器重新分配带来的影响(这在编译器优化中很常见). 其次这里指令比较是模糊匹配, 并且允许部分匹配能容忍这些差异.
  * 基本块比较: 利用动态规划里的`最长公共子序列(LCS)`算法来比较两个基本块(基本块就是指令的序列). 然后利用LCS计算两个基本块的相似性得分. 
  * 最长路径生成: 
    * 对于每个基本块对, 我们可以得到相似度分数. 但这些相似度分数取决于其汇编指令, 如果我们得到了多个指令相似的基本块就认定匹配这样会很糟糕的. 
    * 因此我们还要提取函数的`CFG`的`path`. `path`能记录遇到分支时控制流路径, 一个`path`就是一个完整的执行路径. 
    * 使用`DFS`来遍历`CFG`选择节点最多的路径.
  * 路径探索:
    * 获取目标函数的最长路径后, 就是探索参考函数, 尝试找到最长路径的最佳匹配. 论文结合使用`BFS`和动态规划来计算语义等效基本块的最长公共子序列的最高分.
    * 路径探索算法类似于动态规划计算两个字符串的LCS. 路径也就是基本块的序列, 但与字符串不同的是, 字符串的长度是固定的, 因此其及仪表的长度也是固定的. 在路径探索中并不能预先知道记忆表的长度, 因此将其初始长度设为1, 在运行时动态扩展. 其次字符串是顺序的, 每个字母最多有一个后继, 而CFG路径一个节点可能会有多个后继. 因此我们需要结合BFS和DP
      * 给定目标函数的最长路径P, 参考函数的CFG为G
      * 首先从G的头结点开始, 每次迭代, 从工作队列Q里弹出一个节点作为当前节点
      * 随后向`记忆表`添加新行, 并使用LCS函数更新该表.这里注意我们要求当前节点与路径P中每个节点比较时, 要具有相同的出度和入度. 不然给0分不进入后续匹配.
      * 为提高效率, 重要的是减小搜索空间并剪枝. 于是算法中维护了一个数组用以更新高分数节点, 并将高分数节点的后继节点插入到工作队列Q中去.
  * 领域探索:
    * 使用贪心局部模糊匹配来扩展现有映射. 
    * 将路径探索得到的每个匹配的基本块对放入优先级队列, 然后探索基本块对的邻居节点进行打分
  * 过滤:
    * 根据基本块数量过滤: 设置一个阈值
    * 根据指纹相似性: 计算jaccard相似度并设置阈值
      * Minhashing: 使用K个不同的hash函数来生成minhash签名
      * binding technique: 将minhash签名分成每个r行的b个带
      * 结合这两个技术来设置jaccard阈值

</details>

<details> <summary>Day27: 阅读跨架构二进制代码复用检测论文</summary>

> 传送门: [Semantic-Based Representation Binary Clone Detection for Cross-Architectures in the Internet of Things](https://www.mdpi.com/2076-3417/9/16/3283/pdf)

- [x] 摘要:
  * 许多二进制克隆检测方法不适合各种编译器选项和不同的体系架构.
  * 有些检测方法能应对不同架构, 但是依赖于先验知识人工提取的特征来生成特征向量, 并且无法从语义角度进行特征之间的内部关联
  * GeneDiff利用NLP的`表示模型`, 为基于IR的每个函数生成`高维数值矢量`. 能应对各种编译优化选项和体系架构.
- [x] 介绍:
  * 论文使用受`PV-DM`神经网络启发的`语义表示模型`来解决克隆检测问题. 在此模型里, 指令对应于单词, 基本块对应于句子. 函数对应于段落. `PV-DM`神经网络可以学习每个单词和每个段落的矢量表示, 并将单词的相似含义映射到矢量空间的相似位置. 并且利用NLP能共享许多共性, 比如语义提取, 分类和相似性比较. 
  * GeneDIff使用大量二进制文件来训练`语义表示模型`. 然后利用`表示模型`将来自不同架构的二进制映射为`高维数值向量`. 通过计算`余弦距离`来评估函数高维向量之间的相似性作为评判得分. 
- [x] 问题定义: 
  * 关注函数级别的复用问题. 如果在源码里采用了相似的函数逻辑, 那么其汇编函数就是语义相似的(语法可能略有不同)
  * 给定来自`{X86, ARM, MIPS, AMD64, AArch64, MIPS64}`的二进制文件, 研究的问题就是要针对二进制文件的每个汇编函数来匹配存储库里前K个语义相似的函数.
* GeneDiff的流水线图示:

  ![genediff-flowchart](assets/genediff-flowchart.png)

* GeneDiff组件构成:

  ![genediff-components.png](assets/genediff-components.png)

- [x] Word and Paragraph Embedding: PV-DM是`word2vec`的扩展, 专为段落向量和单词向量而设计. 训练好的PV-DM模型可以根据段落中的单词为每个段落生成段落语义矢量, 这些段落语义矢量可用于段落级别的语义分析和相似性分析. 
* 论文里`PV-DM`的引用: 将每条VEX指令视为一个字母, 将VEX指令的组合视为单词, 基本块视为句子. 函数视为段落. 函数向量的提取有以下问题: 1. 函数之间的调用关系很复杂. 2. 函数的执行流具有多个路径. 3. 每个表达式由多个部分组成. 
* GeneDiff解决函数向量提取的措施:
  1. Callee expansion: 解决编译器优化中函数内联造成的问题(这会实质性地改变控制流). 
  2. Multi-path generation: 通过确保函数基本块全覆盖来生成多条路径. 
  3. Training model: 将每条路径作为输入, 基于语义训练一个表示学习模型, 并将指令和函数映射到高维向量中.

</details>

<details> <summary>Day28: 阅读机器学习APK解混淆论文和代码克隆检测进展</summary> 

> 传送门: [Deobfuscating Android Applications through Deep Learning](https://pdfs.semanticscholar.org/8587/79f77d4934ddab0552fc6817f85d2bc32926.pdf)

- [x] 介绍:
  
  * 论文应用了递归神经网络和深度学习. Macneto通过`topic modeling`学习代码的深层语义来进行解混淆. `topic model`是程序行为的表征, 不受代码布局,CFG结构,元数据等的影响.
- [x] 背景知识:
  * Lexical transformations: 进行标识符(方法/类/变量名)的替换.
  * Control transformations: 内联代码, 分割方法, 重排语句, 添加跳转和其他指令等.
  * Data transformations: 字符串加密, 更改数据结构类型等.
- [x] 概览:
  * 四个阶段:
    1. 计算指令分布: 将方法解析为指令的分布, 类似文档的词频向量. 不仅考虑方法内的指令, 还考虑callee的指令, 认为这样能更深入地理解行为语义
    2. 机器主题建模: 从指令分布汇总识别机器主题. 这些机器主题表征方法的语义. 
    3. 学习: 使用两层RNN, 输入指令分布, 输出机器主题的分布. 
    4. 解混淆: 给定混淆的函数, 训练好的模型会推断其主题分布, 然后尝试查找具有相似主题分布的一组原始方法.

  ![macneto-overview.png](assets/macneto-overview.png)
- [x] 实现: 
  1. 递归地标记所有的callee函数并使用词频分布来计算指令分布.
  2. 使用图扩散算法识别原始方法与混淆方法之间的callee差异.

> 传送门: [代码克隆检测研究进展](https://xin-xia.github.io/publication/rjxb181.pdf)

- [x] 四种代码克隆类型:
  1. 完全相同的代码: 除了空格，注释之外，两个代码片段完全相同的代码对
  2. 重命名/参数化的代码: 除了变量名，类型名，函数名之外都相同的代码对
  3. 几乎相同的代码: 有若干语句的增删，或使用了不同的标识符、文字、类型、空格、布 局和注释，但是依然相似的代码对。
  4. 语义相似的代码: 相同功能的异构代码，在文本或者语法上不相似，但是在语义上有 相似性。
- [x] 各种代码表征方式的研究
  * 基于文本表征方式的研究
  - [x] 基于词汇表征方式的研究
    * CCFinder: 
      1. 词法分析器解析得到符号序列, 去除空格和注释
      2. 符号序列经过一定转化规则进行变形, 将参数替换成符号
      3. 在匹配检测阶段, 使用后缀树匹配算法检测出代码克隆
    * CP-Miner使用`频繁项挖掘`技术来检测大型系统的代码克隆和克隆相关的软件缺陷
  - [x] 基于语法表征方式的研究:
    - [x] 基于AST的方法
      * CloneDR: 
        * 第一个算法检测整棵树中的子树的克隆: 使用哈希来将子树分割然后比较这些子树
        * 第二个算法检测子树中变长序列的克隆
        * 第三个算法结合其他检测方法找到更多的代码克隆
      * Deckard:
        * 使用AST生成一个向量集用于承载AST中的结构信息. 
        * 使用这些相邻用局部敏感哈希算法进行聚类, 从而可以找到一个向量的近邻.
      * CDLH: 
        * 将源代码用AST表征后, 用一定的编码规则进行编码
        * 将编码后的数据输入给CNN进行训练
        * 用训练的特征进行克隆检测
    - [x] 基于指标的方法
      * Mayrand: 以函数名称,层次,表达式, 控制流作为指标
  - [x] 基于语义表征方式的研究:
    * Komondoor: 使用程序切片寻找同构的程序依赖图的子图. 

</details> 

<details> <summary>Day29: 收集二进制代码克隆检测的论文资料</summary> 

![binary-code-clone-detect-papers.png](assets/binary-code-clone-detect-papers.png)

</details> 

<details> <summary>Day30-31: 阅读代码相似性检测论文</summary> 

> 传送门: [Open-source tools and benchmarks for code-clone detection: past, present, and future trends](https://dl.acm.org/doi/abs/10.1145/3381307.3381310)

- [x] 基本定义:
  * Code Fragment: 源代码的连续片段. 表示为`(l,s,e)`, l表示源文件, s表示起始行, e表示结束行
  * Clone Pair: 一对相似的代码片段, 表示为(f1, f2, type)
  * Clone Class: 一组相似的代码片段, 由 (f1, f2, ..., fn, type)表示. 类里两两不同的函数可以组成clone pair
- [x] 克隆分类: 
  * 语法克隆: 基于其文本相似
    * Type-1: 除开空格和注释外, 两个完全相同的片段
    * Type-2: 两个片段相似的代码, 只是重命名了一些标识符. 
    * Type-3: 相比Type-2, 片段可能经过了修改, 比如添加/删除了部分代码, 代码块中的语句经过了重新排序.
  * 语义克隆: 基于功能相似
    * Type-4: 语法上不相似但语义相似
- [x] 克隆检测步骤
  1. 预处理: 
    * 首先, 移除掉所有在比较过程中不会造成影响的元素
    * 其次, 通过多种方式(比如词法分析/AST)将源代码划分为单独的片段(例如类, 函数, 基本块, 语句等)将其转换为单元. 这些单元用于检查直接的克隆关系是否存在. 
    * 最后定义比较单元, 比如可以将单元分为各个token
  2. 转换:
    * 将源代码转换成相应的IR进行比较. 
    * 可以从源代码构造很多类型的表示形式, 例如token stream, 其中源码的每一行都转换成了token序列. 
    * 另一个常见构造就是AST. 以子树来进行比较
    * 此外, 可以提取为程序依赖图(PDG), PDG能表示控制和数据依赖关系, PDG通常使用源代码中的语义感知技术来进行子图比较.
  3. 匹配检测: 将每个转换的代码片段与其他片段进行比较, 以找到相似的源代码片段.
- [x] 旧时代检测技术
  * 1992年基于逐行比较, 从源代码文件中删除空格和注释
  * 1995年, 使用"参数化"的思想, 将唯一标识符(例如变量名, 方法名等)替换为唯一的字符. 来发现Type-1和Type-2型克隆
  * 1998年, CloneDR比较AST进行树匹配, 以找到精确匹配或近似精确匹配. 
  * 2002年. CCFinder扩展了检测的词汇性质. 它标记了源代码文件, 并使用了一组特定于语言的词汇规则来转换token流. 使用前缀树和新颖匹配算法, 计算令牌的常见前缀以发现代码复用
  * CP-Miner在代码克隆之间增加了bug检测
  * 2007年DecKard将AST转换为特征向量, 将向量聚类以减少比较. 能够检测Type-3类代码克隆
- [x] Benchmark
  * 2007年Bellon通过两个小型C程序和两个小型Java程序运行6个不同的代码克隆工具而收集的
  * 近年, BigCloneBench是IJaDataset-2.0(一个包含25,000个开源Java系统的大数据软件存储库)中800万个经过验证的克隆数据集. 包括四种主要克隆类型的项目内和项目间克隆.
- [x] [Open-source tools and benchmarks for code-clone detection: past, present, and future trends](https://dl.acm.org/doi/abs/10.1145/3381307.3381310)
  * Textual: 比较代码片段的`文本/字符串/词素`
  * Token-Based Approaches: 词法分析将源代码划分成一系列的token. 匹配token序列
  * Syntactical Approaches: 基于`树`或基于`尺度`. 基于树则是指AST, 用子树来识别相似区域. 基于尺度则是从源代码收集各种尺度来创建单独的向量, 通过比较向量来找到相似区域
  * Semantic Approaches: 主要基于图. 构造程序依赖图(PDG)来表示源代码的控制流和数据流. 比较两个PDG来识别程序两个版本之间语法和语义的差异. 
  * Learning Approaches: 分为机器学习和其他基于学习的技术. 跟学习方法类似的还有数据挖掘的方法. 

- [x] RetroWrite: Statically Instrumenting COTS Binaries for Fuzzing and Sanitization
- [x] Detecting Code Clones with Graph Neural Network and Flow-Augmented Abstract Syntax Tree: 提出了增强AST的想法, 增加了next关联以及`if/while/for/seq`结构的关联
- [x] Semantic Representation Learning of Code based on Visualization and Transfer Learning Patrick: 将源代码结构转换成图片(提取视觉结构), 通过训练好的图片分类神经网络生成代表图像结构信息的特征矢量. 得到特征矢量后再训练一个分类器用于分类或克隆检测. 
  * Plain Text: 将代码的纯文本表示形式渲染为黑白图像
  * Color Syntax Highlighting: 在纯文本的基础上增加代码高亮
  * Geometric Syntax Highlighting: 将语法关键字用特定的几何形状来表示(用于标记).
  * Ast in Condensed Format: 对AST进行可视化渲染. 
- [x] Clone Detection on Large Scala Codebases
  * SourcererCC: 将代码片段表示为一堆token, 通过比较token的重叠程度来评估相似度. 
  * AUTOENCODE: 使用`标识符`, `AST`, `字节码`, `CFG`生成嵌入输入给深度学习模型. 通过计算距离来评估相似度
- [x] DEEPBINDIFF: Learning Program-Wide Code Representations for Binary Diffing Yue
  * Bindiff: 在call graph和cfg上进行图的同构检测, 并通过`函数名/图边MD索引`来匹配函数和基本块.
  * DeepBindiff: 提取ICFG(过程间CFG). 还通过每个基本块生成特征向量, 也就是生成token嵌入和生成特征向量. token是取的操作码和操作数. 
- [x] Similarity Metric Method for Binary Basic Blocks of Cross-Instruction Set Architecture
  * 8个特征: 字符串常量, 数字常量, 转移指令数量, 调用数量, 指令数量, 算术指令数量, 子孙数量, 中间块
  * 汇编指令的标准化:
    * 常量: 立即数, 地址, 变量名, 函数名, 基本块标签
    * 寄存器: x86有14类寄存器 ARM被标准化为2类
- [x] Asm2Vec: Boosting Static Representation Robustness for Binary Clone Search against Code Obfuscation and Compiler Optimization Steven
  * 将CFG拆分成序列, 这里的序列是一个可能的执行路径.
  * 对于一个序列, 通过PV-DM, 用序列中相邻的指令去预测中间的汇编指令. 以此来训练.

</details> 

<details> <summary>Day32: 阅读20年S&P最佳实践论文</summary>

> 传送门: [An Analysis of Pre-installed Android Software](https://arxiv.org/pdf/1905.02713.pdf)

- [x] Data Collection:
  * 使用Firmware Scanner做固件扫描, 使用Lumen来获得网络流数据. 
- [x] ECOSYSTEM OVERVIEW:
  * 首先分析预装APK里的证书, 通过证书将APK进行聚类, 用证书里的`Issuer`字段来区分组织. 不过厂商可以使用多个证书, 并且这些证书并非完全可信
  * 实践中有遇到使用`Android Debug`证书签名的APK, 这是开发时用的调试证书. 也有的证书仅提及`Android`未明确表明组织
  * 使用LibRadar++来识别APK中使用的第三方库. 预装的APK中存在第三方库的话, 是有风险监控到用户活动的. 实践表明存在第三方库, 比如Facebook的SDK有部分由设备厂商签名, 部分由运营商签名, 只有小部分由Facebook签名. 同样对于中国的一些SDK, 实践表明只有极小部分是由实际的第三方服务提供商签名, 也就意味着第三方库的引用决定在于APK的开发者. 
  * 对Google Play的APK进行爬取, 来判断有多少Android固件中预装的APK能在应用商店里公开获得. 实践表明只有9%的APK能在Google Play商店找到, 而找到的这部分也很少是预装APK的范畴, 主要是一些通信/娱乐/工具等的通用性APK
  * 使用Androguard提取APK里声明和请求的权限. 主要关注自定义权限, 因为预装的服务具有对系统资源的特权访问, 并且预装服务可能(非用户自愿地)公开关键服务和数据, 甚至绕过ANdroid的官方权限
- [x] Behavioral Analysis
  * 集成各种静态分析工具, 比如Androwarn, FlowDroid, Amandroid, APktool, Androguard.

</details> 

<details> <summary>Day33-40: 阅读代码相似性检测论文</summary>

> 传送门: [LibDX: A Cross-Platform and Accurate System to Detect Third-Party Libraries in Binary Code](https://ieeexplore.ieee.org/document/9054845)

* LibDX: 从第三方程序包二进制中`识别出特征文件`, `提取特征`和`建立胎记`并最终构建一个`特征数据库`. 拿到样本的时候就提取特征跟数据库进行匹配. 由于匹配的时候会因为规模庞大, 因此LibDX的解决方案是识别逻辑功能块, 然后生成目标的基因图进行筛选. 
* LibDX需要处理多种文件架构和特征冗余的问题. 对于多种架构, LibDX试图提取平台无关的指纹做参考. 而特征冗余. LibDX使用的是源代码和二进制代码之间均不变的字符串常量做特征, 但是对于内部的代码复用是难以解决的. 这里分为两种: `父子节点`和`变体库`
  * 父子节点就是, 子节点未LibPNG, 父节点为OpenCV. 存在可能报告LibPNG的时候把父节点也匹配出来. 解决方案是分层. 
  * 变体库: 比如libijg是在libjpeg基础上重新开发, 这之间仅存在细微的差别, 所以应该将变种库的打分跟原始库一致
* 一些字符串常量在多个库中重复, 但不是由代码克隆而引起的. 比如有的字符串常出现在内存里, 因此需要一种权重函数来减少经常使用的字符串所贡献的分数. 
* 字符串的权重使用TF-IDF系数进行计算
* 利用文件的只读数据段, linux的`.rodata`, windows的`.rdata`, macos的`__cstring`. 

> 传送门: [Detecting Code Clones with Graph Neural Network and Flow-Augmented Abstract Syntax Tree](https://arxiv.org/pdf/2002.08653.pdf)

* 使用显式控制和数据流边缘扩展原始的AST来构造增强的FA-AST, 然后在FA-AST上应用两种不同的图神经网络来测量代码对的相似性. 
* 传统基于深度学习的方法: 使用神经网络为每个代码片段计算向量表示, 然后计算两个代码向量表示之间的相似度以检测克隆. 
* 尽管AST可以反映语法的结构信息, 但是不包含某些语义信息比如控制流和数据流
* 论文方法: 首先为程序创建图形表示, 然后使用图神经网络为代码片段计算矢量表示, 最后通过测量代码向量表示的相似性来测量代码相似性. 使用的两种GNN模型: 门控图神经网络GGNN和图匹配网络GMN. GGNN用于计算不同代码片段的向量表示, GMN用于测量代码对的向量表示的相似性. 

> 传送门: [Order Matters: Semantic-Aware Neural Networks for Binary Code Similarity Detection](https://keenlab.tencent.com/en/whitepapers/Ordermatters.pdf)

* 论文提出了语义感知的神经网络来提取二进制的语义信息, 使用BERT对token级, block级和两个graph级别的任务进行与训练. 此外, 发现CFG节点的顺序对于图相似度检测很重要, 因此论文在邻接矩阵上采用CNN来提取顺序信息. 
* Gemini: 将CFG里的各个基本块转换成手动选取特征代替的另一种块(用特征向量来代替基本块), 然后用Structure2vec来生成图嵌入, 最后添加siamese架构来计算相似度.
  * 问题1: 每个块都用一个手动选取特征的低维向量表示, 这会导致大量的语义信息丢失. 
  * 问题2: 节点的顺序在二进制函数的表示中起了重要做哟个. 
  * 论文要点: 提出了语义感知模型, 结构感知模型和次序感知模型
* 语义感知模型: 使用NLP提取二进制代码的语义信息, CFG基本块中的token被视为单词, 而基本块视为句子. 论文使用BERT来对token和block进行预训练. 然后在标记语言模型任务(MLM)上标记要预训练的token, 并在邻接节点预测任务(ANP)上提取所有即将与训练的相邻基本块. 
* 另外还有两个图级的任务:
  * BIG(block inside graph task): 确定两个采样的基本块是否在同一个图内
  * GC(graph classification task): 区分该基本块属于哪一个平台/优化. 
* 结构感知模型: 结合使用MPNN和GRU来更新函数. 
* 次序感知模型: 设计了一个邻接矩阵来记录各个基本块的次序. 次序感知基于的前提是实践观察到其变化很小, 因此将该信息进行捕捉. 

> 传送门: [Similarity Metric Method for Binary Basic Blocks of Cross-Instruction Set Architecture](https://www.ndss-symposium.org/wp-content/uploads/bar2020-23002.pdf)

* 论文使用NMT(神经机器翻译)模型连接两个ISA的基本块, 提出的嵌入模型可以将来自任意ISA的基本块的丰富语义映射到固定维的向量中. 
* NMT模型: 建立在seq2seq架构上, 该架构包括`编码器`和`解码器`. 编码器将源文本编码为`上下文矩阵`, 解码器将`上下文矩阵`解码为目标文本. 在理想情况下(也就是源文本能够无损地翻译为目标文本), 上下文矩阵可以完整地包含源文本和目标文本的语义信息. 
* 论文建立了NMT模型将x86的基本块转换成ARM. 将这中间的上下文矩阵转换成固定维的向量来生成块嵌入. 然后通过块嵌入的相似性进行评估. 
* 汇编指令的标准化方法: 将常量分为`立即数/地址/变量名/函数名/基本块标签`进行符号化. 类似地寄存器也有集中类型的符号表示. 

> 传送门: [A Cross-Architecture Instruction Embedding Model for Natural Language Processing-Inspired Binary Code Analysis](https://arxiv.org/pdf/1812.09652.pdf)

* 论文希望使得行为类似的指令(无论属于何种架构)都能具有相近的嵌入, 因此提出了`联合学习`的方法来生成嵌入. 该嵌入不仅能捕获架构内指令的语义, 也能捕获跨架构的语义关系. 
* 传统方法: 基于字符串, AST, token, PDG
* 论文构建指令模型, 希望学习到的跨体系结构指令嵌入, 不仅在单体系结构上保留聚类属性, 还要展现出不同体系结构之间的语义关联关系. 
* 对于NLP的OOV问题, 需要处理常量/地址偏移/标签/字符串等值. 解决方法就是符号化.
* 论文里将多种架构里的指令语义进行了相互关联预测. 比如对于两个上下文中, x86的指令跟arm的指令语义相同, 那么就可以用arm指令周围的指令来预测x86的等效指令. 但这里就需要找到指令的语义等价连接, 可以使用操作码对齐的方式, 然后通过DP的最长公共子序列来确定两个序列之间的最佳比对. 

> 传送门: [Statistical similarity of binaries](https://dl.acm.org/doi/10.1145/2980983.2908126)

* 论文受图的局部相似性匹配启发, 用统计的方法通过函数切片的局部匹配得分来计算全局的匹配得分. 
  * Decomposing the procedure into strands: 将函数分解成多个切片
  * Comparing strands: 使用program verifier通过假设输入等价并检查中间值和输出值, 以此来检查两条链在语义上是否等价
  * Statistical reasoning over strands: 用切片之间的局部证据得分(LES)的总和来计算函数之间的全局相似性得分. 同时放大了高LES表示的特有链的相似性得分, 减少了常见链的得分, 做了这样的差异化. 
* 使用工具将汇编转换成了中间验证语言(IVL). 对于需要比较的一对切片, 则会给定输入和输出的断言, 然后通过verifier来检查这些断言是否生效, 然后统计有多少变量是等价的. 

> 传送门: [BinMatch: A Semantics-based Hybrid Approach on Binary Code Clone Analysis](https://loccs.sjtu.edu.cn/~romangol/publications/icsme18.pdf)

* 使用测试用例执行模板函数并记录运行时的信息(比如函数参数), 然后将信息迁移到每个候选目标函数并模拟执行, 在执行过程中, 记录模板和目标函数的语义签名. 根据比较模板函数和每个目标函数的签名来计算相似度.
* 语义签名, 包含以下特征
  * 读取和写入的值: 该函数在模拟执行期间从内存读取和写入内存的全局(或静态)变量值组成. 当包含特定输入时, 它会包含函数的输入和输出值, 指示函数的语义
  * 比较操作数值: 由比较操作的值组成. 这些操作的结果决定了模拟执行的后续控制流. 它指示了输入值生成输出的路径. 
  * 标准库函数: 标准库为实现用户定义函数提供了基本的函数. 这个特征已被证实跟语义相关, 并对代码克隆分析有效.
* 插装和执行
  * 通过分析汇编, 在语义特征位置处插入代码以获取和生成函数特征. 
  * 同时记录运行时的信息, 比如函数参数, 调用函数地址, 返回值等
* 模拟执行: 相似的函数在相同输入的情况下行为也应当是一致的.
  * 函数参数分配: 克隆函数具有相同的参数数量. 因此在执行时确定函数数量, 数量一致再根据调用约定填入参数
  * 全局变量读取: 不仅要迁移到相同的全局变量, 还要保证全局变量的使用顺序一致. 如果没有足够的全局变量值进行分配, 使用预定义的0xdeadbeef
  * 间接调用/跳转: 通过确认模拟执行期间的调用目标来判断是否是克隆函数. 跳转表保存在.rodata里
  * 标准库函数调用: 记录库函数调用的返回值, 模拟时直接返回就不去执行了. 
  * 使用LCS(最长公共子序列)算法进行相似性测量, 而相似度分数则使用Jaccard Index来衡量.
* 实现: 使用IDA来获取基本块信息, 使用Valgrind进行插装, 基于angr进行模拟执行. 因为签名的内存占用很高, 所以使用Hirschberg算法进行实现LCS, 该算法有着可观的内存占用复杂度. 

> 传送门: [αDiff: Cross-Version Binary Code Similarity Detection with DNN](https://dl.acm.org/doi/pdf/10.1145/3238147.3238199?download=true)

* 提取了3个语义特征: 函数代码特征(函数内), 函数调用特征(函数间)和模块交互特征(模块间). 输入函数的原始字节值给CNN进行训练将其转换成一个embedding(也就是向量), 然后加入到暹罗网络中去. 其次, 在提取函数间特征的时候, 出于性能考虑, 仅提取了调用图中函数节点的入度和出度作为函数特征. 第三, 分析每个函数的导入函数(imports)并将其用作模块间特征, 并设计算法将其嵌入为一个向量来计算距离. 

> 传送门: [Binary Similarity Detection Using Machine Learning](https://dl.acm.org/doi/10.1145/3264820.3264821)

* 基于并行机器学习的组成原理的相似性, 提出了proc2vec的方法, 将过程(或代码段)表示为向量. proc2vec会将每个过程分解小的段, 将每个段转换为规范形式, 并将其文本表示形式转换成数字, 从而将每个过程转换成向量空间里的embedding. 
* 基于之前统计方法里的`strand`概念, `strand`是代码块中计算某个变量的值所需要的一组指令.
* prov2vec:
  1. 将过程切分成基本块.  
  2. 将基本块切分成strand
  3. 语义相同但语法不同的strand则会转换成相同的文本表示
  4. 使用b-bit MD5哈希算法将文本表示进行处理. ? 迷惑行为, 哈希之后还算什么语义?
  5. 使用哈希值组成向量输入给神经网络.

> 传送门: [VulSeeker: A Semantic Learning Based Vulnerability Seeker for Cross-platform Binary](https://dl.acm.org/doi/10.1145/3238147.3240480)

* VulSeeker, 基于语义学习的跨平台二进制漏洞查找程序. 给定目标函数和易受攻击的函数, VulSeeker首先构造`标记语义流图(LSFG)`(labeled semantic flow graph)并提取基本块特征作为这两个函数的数值向量, 然后将数值变量输入给定制的DNN模型, 生成嵌入向量. 然后基于余弦距离计算两个二进制函数的相似性. 
* LSFG就是结合了CFG和DFG的简化图. 另外提取了8种特征并将其编码组成向量: 栈操作指令数量, 算术指令数量, 逻辑指令数量, 比较指令数量, 库函数调用指令数量, 无条件跳转指令数量, 有条件跳转指令数量, 通用指令数量. 

> 传送门: [FirmUp: Precise Static Detection of Common Vulnerabilities in Firmware](https://dl.acm.org/doi/10.1145/3296957.3177157)

* 现代二进制程序会需要适应不同的环境和需求进行构建, 从而导致功能上的巨大差异, 比如wget可以在支持/不支持SSL的情况下分别编译, 而cURL也可以在不支持cookie的情况下编译. 这会导致结构上的巨大差异, 并阻碍了达到完全同构的可能. 
1. 在统计篇的基础上, 进一步改进了strand. 
2. 将过程相似性扩展到过程外去观察相邻的过程. 这是实践观察的经验, 观察到过程始终在程序内部进行操作, 因此几乎总是会和相邻的某些过程一起出现. 使用相邻过程的信息可以提高准确性
3. 优化了匹配过程. 受往复博弈(back-and-forth games)的启发, 但匹配的集合非常大(但不是无限)时, 该博弈能更有效低替代全匹配算法. 

> 传送门: [FOSSIL: A Resilient and Efficient System for Identifying FOSS Functions in Malware Binaries](https://dl.acm.org/doi/10.1145/3175492)

* FOSSIL: 包含三部分, 1. 使用隐式马尔科夫链模型统计操作码频率以此来作为函数的句法特征. 2. 应用领域哈希图在CFG上进行随机游走, 以提取函数的语义特征. 3. 使用`z-score`对指令进行规范化, 以提取指令的行为. 然后将这三部分组件使用贝叶斯网络模型整合在一起, 对结果进行综合评估来检测开源软件函数. 
* 汇编指令的规范化: 将常量值和内存应用规范化为V和M来表示. 而寄存器的规范化可以分级别, 比如将所有寄存器都用REG表示, 或者只区分通用寄存器/段寄存器/索引/指针寄存器等, 或者用寄存器的大小分为3类: 32/16/8位寄存器.
* 在CFG上进行随机游走以获得路径序列, 找到两个基本块节点之间的最短路径. 

> 传送门: [Beyond Precision and Recall: Understanding Uses (and Misuses) of Similarity Hashes in Binary Analysis](https://dl.acm.org/doi/10.1145/3176258.3176306)

* Context-Triggered Piecewise Hashing: CTPH通过局部的相似来推测文件的相似, LBFS通过计算n字节上下文的滑窗进行哈希, 确保插入或删除短字符串仅会更改哈希的几个文件块而其余保持不变. 
* Statistically Improbable Features: sdhash能够寻找统计上的特异字节序列(特征), 比如较长但不寻常的某一共同字符串.
* N-grams: 相似的文件具有相似的n-gram频率分布.  
* 实验表明tlsh和sdhash始终优于ssdeep.

> 传送门: [BCD: Decomposing Binary Code Into Components Using Graph-Based Clustering](https://dl.acm.org/doi/10.1145/3196494.3196504)

* 将binary分解为组件图, 节点为函数, 边表征三种关系: 代码局部性, 数据引用, 函数调用. 然后实验图论方法将函数划分为不相关的组件. 
* Code locality to sequence graph (SG): 程序员开发时会将结构相关的函数放在源代码彼此相近的位置. 
* Data references to data-reference graph (DRG): 处理相同数据的函数更有可能是结构相关的, 因为它们都有相同的数据语义. BCD通过访问相同变量的函数之间添加边来构造数据引用图. 只关注静态数据, 全局变量和字符串. 
* Function calls to call graph (CG): 两个函数之间的调用次数越多, 它们的结构关系越强, 也就增加相应的边的权重

> 传送门: [Binary code clone detection across architectures and compiling configurations](https://dl.acm.org/doi/10.1109/ICPC.2017.22)

* 将目标与每个模板函数进行比较, 找到最相似的函数. 
* 首先识别函数传递的参数以及switch语句的可能跳转目标. 然后通过IR将不同架构的bianry统一表示起来, 并模拟这些二进制的执行以提取语义签名. 最后, 计算每个模板函数与每个目标函数的相似性分数, 返回分数排序的匹配函数列表. 
* 处理流程: 反汇编二进制代码, 生成CFG, 收集CFG里基本块和边的信息. 然后遍历CFG以识别执行函数所需的参数, 收集所有可能的间接跳转地址(switch语句). 将二进制转换成IR, 接下来, 使用参数和switch的信息, 将IR形式的函数模拟执行起来, 用于生成语义签名.  最后将每个目标函数的签名与模板函数进行比较, 得到相似函数列表. 
  
> 传送门: [Benchmarks for software clone detection: A ten-year retrospective](https://ieeexplore.ieee.org/document/8330194)

> 传送门: [The adverse effects of code duplication in machine learning models of code](https://dl.acm.org/doi/pdf/10.1145/3359591.3359735)

* 论文主要在测量代码重复在机器学习模型中造成的副作用. 代码重复是指大量的几乎没有差别的重复代码片段. 
* 代码重复的问题在于实践中, 研究人员很少通过直接观察其训练模型的结果造成的, 相反常见的作法是将数据集分为两部分, 一部分用作训练一部分用来做测试. 但由于重复数据集的分布方式和非重复数据集的分布方式不同, 因此机器学习模型将学习不同的概率分布进行建模. 而机器学习里的一个重要的假设就是, 每个数据点都必须独立且在使用的数据集上具有等同的分布. 因此在许多机器学习代码检测代码相似的模型里都严重违反了该原则. 
* 三种类型的代码重复: 
  * in-train duplicates: 在训练集里的重复文件
  * in-test duplicates: 在测试集里的重复文件
  * cross-set duplicate: 训练集和测试集均出现的重复文件
* 论文通过修改SourcererCC代码, 对文件进行精确匹配. 而对于那些只有微量改动的重复文件, 则通过构建指纹(标识符和文字), 计算jaccard距离超过阈值(0.7和0.8), 来检测这种重复文件(此外指纹数量少的文件也会直接忽略掉). 

</details>

<details> <summary>Day41: 安装和了解Unicorn框架和示例代码</summary>

* 安装: `UNICORN_ARCHS="arm aarch64 x86" ./make.sh ; sudo ./make.sh install`. 安装Python binding: `pip install unicorn`
* CPU模拟执行的原理:
  * 给定二进制文件, 将二进制解码成单独的指令
  * 对每一条指令进行模拟, 需要解决ISA引用和内存访问&I/O请求
  * 执行指令更新CPU的上下文(寄存器/内存/等等)
* showcase里的代码释义:
  * `mu = Uc(UC_ARCH_X86, UC_MODE_32)`: 初始化模拟器为x86_32模式
  * `mu.mem_map(ADDRESS, 2 * 1024 * 1024)`: 映射2MB内存用于模拟, Address是模拟的起始内存地址
  * `mu.mem_write(ADDRESS, X86_CODE32)`: 将机器码写入到起始地址内存中
  * `mu.reg_write(UC_X86_REG_ECX, 0x1234)`: 设置寄存器的初始值, 这里是ECX寄存器
  * `mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32))`: 开始模拟, 参数为内存起始和结束地址
  * `mu.reg_read(UC_X86_REG_ECX)`: 读取寄存器的值
* 阅读仓库内的Python示例代码: [传送门](https://github.com/unicorn-engine/unicorn/blob/master/bindings/python/README.TXT)
  * `mu.hook_add(UC_HOOK_BLOCK, hook_block)`: 添加一个hook, 第一个参数是hook类型, 第二个参数是hook后的回调函数.

</details>

<details> <summary>Day42-43: 安装配置Manjaro+i3wm桌面环境</summary>

以下是我安装完Manjaro-i3后的配置记录. 我的配置文件存放在: [dotfiles](https://github.com/Vancir/dotfiles)

* 0x01 添加国内源

``` bash
sudo pacman-mirrors -i -c China -m rank
# 选择清华和中科大的源
sudo vim /etc/pacman.conf
## 填入以下内容
[archlinuxcn]
SigLevel = Optional TrustedOnly
Server = https://mirrors.ustc.edu.cn/archlinuxcn/$arch
Server = http://mirrors.tuna.tsinghua.edu.cn/archlinuxcn/$arch

[antergos]
SigLevel = TrustAll
Server = http://mirrors.tuna.tsinghua.edu.cn/antergos/$repo/$arch

[arch4edu]
SigLevel = TrustAll
Server = http://mirrors.tuna.tsinghua.edu.cn/arch4edu/$arch
# 将Color的注释删去

# 运行以下命令进行更新
sudo pacman -Syy
# 导入GPG
sudo pacman -S archlinuxcn-keyring 
sudo pacman -S antergos-keyring
# 更新系统
sudo pacman -Syu
```

* 0x02 安装常用CLI工具及软件

``` bash
sudo pacman -S yay git firefox netease-cloud-music screenkey tmux aria2 google-chrome feh rofi polybar betterlockscreen pywal-git imagemagick thefuck visual-studio-code-bin intellij-idea-ultimate-edition lxappearance deepin-wine-tim deepin-wine-wechat dolphin redshift deepin-screenshot foxitreader p7zip the_silver_searcher tig wps-office ttf-wps-fonts mpv
```

* 0x03 安装设置Rime输入法

``` bash
yay -S fcitx fcitx-im fcitx-configtool fcitx-rime
# 设置环境变量asd
vim ~/.xprofile
## 填入以下内容
export GTK_IM_MODULE=fcitx
export QT_IM_MODULE=fcitx
export XMODIFIERS=@im=fcitx
# 重新启动/重新登录
sudo reboot
# 填写rime输入法的配置文件
vim ~/.config/fcitx/rime/default.custom.yaml
## 填入以下内容重新部署rime/重启fcitx即可生效
patch:
  schema_list:
    - schema: luna_pinyin_simp
    
  "ascii_composer/switch_key":
    Caps_Lock: noop
    Shift_L: commit_code 
    Shift_R: inline_ascii

  "punctuator/full_shape":
    "/": "/"
  "punctuator/half_shape":
    "/": "/"

  "menu/page_size": 9
# 编辑~/.i3/config文件填入下面这行
exec_always --no-startup-id fcitx
```


* 0x04 解决音频输出的问题

``` bash
yay -S pulseaudio pavucontrol
pulseaudio --start
# 打开pavucontrol配合alsamixer将音量调高
# 然后右键下方状态栏最右边的声音按钮, 将输出调为耳机
```

* 0x05 配置NeoVim

``` bash
yay -S neovim
# 安装vim-plug插件. 
sh -c 'curl -fLo "${XDG_DATA_HOME:-$HOME/.local/share}"/nvim/site/autoload/plug.vim --create-dirs \
       https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim'

# 将我的neovim配置复制到~/.config目录下
# 打开neovim执行 :PlugInstall 
```

* 0x06 配置Fish Shell

``` bash
yay -S fish
chsh -s /usr/bin/fish
# 挑一个喜欢的配色和提示符
fish_config 
```

* 0x07 配置ZSH Shell

``` bash
yay -S zsh
# 安装oh my zsh
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
# 安装插件
git clone git://github.com/zsh-users/zsh-autosuggestions $ZSH_CUSTOM/plugins/zsh-autosuggestions
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting
# 编辑~/.zshrc
ZSH_SHELL="steeef"
plugins=(
	git
	zsh-autosuggestions
	zsh-syntax-highlighting
	z
	extract
	colored-man-pages
	fzf
)
# 修改提示符的样式
PROMPT=$'
%{$purple%}#${PR_RST} %{$orange%}%n${PR_RST} %{$purple%}@${PR_RST} %{$orange%}%m${PR_RST} in %{$limegreen%}%~${PR_RST} %{$limegreen%}$pr_24h_clock${PR_RST} $vcs_info_msg_0_$(virtualenv_info)
%{$hotpink%}$ ${PR_RST}'
```

* 0x08 安装终端软件alacritty

``` bash
yay -S alacritty
vim ~/.config/i3/config
# 将终端修改为alacritty
```

* 设置ZSH配置

``` bash
alias c clear
alias aria2c aira2c -s16 -x16
alias setproxy="export ALL_PROXY=XXXXXXX"
alias unsetproxy="unset ALL_PROXY"
alias ip='curl ip.sb'
alias grep='grep --color=auto'
alias ra='ranger'
```

* 安装字体图标主题等

``` bash
yay -S papirus-icon-theme wqy-microhei ttf-font-awesome

yay -S ttf-linux-libertine ttf-inconsolata ttf-joypixels ttf-twemoji-color noto-fonts-emoji ttf-liberation ttf-droid ttf-fira-code adobe-source-code-pro-fonts

yay -S wqy-bitmapfont wqy-microhei wqy-microhei-lite wqy-zenhei adobe-source-han-mono-cn-fonts adobe-source-han-sans-cn-fonts adobe-source-han-serif-cn-fonts
```

*  配置Rofi

``` bash
yay -S pywal-git
mkdir -p ~/.config/wal/templates
# 使用https://github.com/ameyrk99/no-mans-sky-rice-i3wm里的.i3/rofi.rasi放置在templates目录下
# 并重命名为config.rasi
# 编辑~/.i3/config将mod+d由dmeun修改为rofi
bindsym $mod+d exec rofi -show run
```

* 同步时间

``` bash
sudo hwclock --systohc
sudo ntpdate -u ntp.api.bz
```

* 调准鼠标滚轮速度

``` bash
yay -S imwheel
vim ~/.imwheelrc
# 填入以下内容
".*"
None,      Up,   Button4, 4
None,      Down, Button5, 4
Control_L, Up,   Control_L|Button4
Control_L, Down, Control_L|Button5
Shift_L,   Up,   Shift_L|Button4
Shift_L,   Down, Shift_L|Button5
# 将imwheel写到i3的配置里自动启动, 或者直接执行imwheel也行
imwheel
```

* 配置compton毛玻璃特效

``` bash
# manjaro i3自带compton, 但是该版本只能半透明而无法实现毛玻璃特效
# 我们需要使用另一个分支版的compton
# 卸载预装的compton
yay -Rc picom
# 需要安装asciidoc
yay -S asciidoc
git clone https://github.com/tryone144/compton
cd compton
make 
sudo make install
# 编辑 ~/.config/compton.conf里的opacity
```

* 配置polybar

把配置文件放进去将可以

* 安装WPS

``` bash
sudo pacman -S wps-office
sudo pacman -S ttf-wps-fonts
sudo vim /usr/bin/wps
# 在shebang下面填入
export XMODIFIERS="@im=fcitx"
export QT_IM_MODULE="fcitx"
```

</details>

<details> <summary>Day44: 快速上手学习Go语言</summary>

> 参考: [菜鸟教程-Go语言](https://www.runoob.com/go/go-program-structure.html)

* 安装Golang: `yay -S go`, 使用`go run xxx.go`直接运行程序(可能也是以main作为入口把). 使用`go build`进行编译
* 标识符以`大写字母`开头, 那么这个标识符可以被外部包的代码所使用(导出的, 类似publick). 如果标识符以`小写字母`开头, 则对包外是不可见的, 但是他们则整个包的内部是可见并可用的(类似protected).
* `{`不能单独放在一行(微软写法落泪)
* 一些不太熟悉的保留字: `interface, select, defer, go, map, chan, fallthrough`
* Go语言中变量的声明必须使用空格隔开: `var age int`
* 派生类型: 指针类型, 数组类型, 结构化类型, `Channel`类型, 函数类型, `切片类型`, `接口类型(interface)`, `Map类型`.
* 声明变量: `var identifier type`, 可以一次声明多个变量: `var identifier1, identifier2 type`. 变量声明时如果没有初始化, 则默认为`零`值, `零值`包括`0, false, "", nil`
  * `v_name := value` 这样的写法可以省略`var`, 但是要求`v_name`必须是一个之前没有声明的新变量. 否则会产生编译错误.
  * 多变量声明: 
    * `var vname1, vname2, vname3 = v1, v2, v3`
    * `vname1, vname2, vname3 := v1, v2, v3` 这种格式只能在函数体中出现
    * 以下这种因式分解关键字的写法一般用于声明全局变量
    ``` go
    var (
      vname1 v_type1
      vname2 v_type2
    )
    ```
  * 如果你声明了一个局部变量却没有在相同的代码块中使用它, 同样会得到编译错误. 此外，单纯地给局部变量赋值也是不够的，这个值必须被使用. 
  * 全局变量是允许声明但不使用的. 
  * 空白标识符`_`也被用于抛弃值, 如值 5 在：`_, b = 5, 7` 中被抛弃. 因为Go是必须使用所有被声明的变量的, 但是有时候你并不需要使用从一个函数得到的所有返回值. 
* 常量声明: `const identifier [type] = value`. Go能推断类型所以可以省略type
  * 常量也可以用作枚举: 
    ``` go
    const (
        Unknown = 0
        Female = 1
        Male = 2
    )
    ```
  * 常量可以用`len(), cap(), unsafe.Sizeof()`函数计算表达式的值。常量表达式中，`函数必须是内置函数`，否则编译不过. 
* switch语句从上到下逐一测试, 直到匹配为止. 匹配项后面也不需要再加break. 如果我们需要执行后面的case, 可以使用`fallthrough`. `fallthrough`会强制执行下一条case语句.
* switch语句还可以用于`type-switch`来判断某个interface变量中实际存储的变量类型
  ``` go
  var x interface{}
     
  switch i := x.(type) {
    case nil:  
       fmt.Printf(" x 的类型 :%T",i)                
    case int:  
       fmt.Printf("x 是 int 型")                      
    case float64:
       fmt.Printf("x 是 float64 型")          
    case func(int) float64:
       fmt.Printf("x 是 func(int) 型")                      
    case bool, string:
       fmt.Printf("x 是 bool 或 string 型" )      
    default:
       fmt.Printf("未知型")    
  }  
  ```
* select 是 Go 中的一个控制结构, 类似于用于通信的 switch 语句. `每个case必须是一个通信操作, 要么是发送要么是接受`
  ``` go
  select {
    case communication clause  :
       statement(s);      
    case communication clause  :
       statement(s);
    /* 你可以定义任意数量的 case */
    default : /* 可选 */
       statement(s);
  }
  ```
* Go中通过`方法`来实现面向对象
* 数组: `var variable_name [SIZE] variable_type`
* Go中的`接口`, 可以将所有的具有共性的方法定义在一起, 任何其他类型只要实现来这些方法就是实现了这个接口(类似抽象方法? 继承?)
* Go使用内置的错误接口来提供简单的错误处理机制. 使用`error.New(msg)`
* 使用`go`关键字来开启`goroutine`, `goroutine`是轻量级线程, 调度由Golang运行时进行管理.
* channel是用来传递数据的一个数据结构. 可用于两个goroutine之间通过传递一个指定类型的值来同步运行和通讯. 操作符`<-`用于指定通道的方向, 发送或接受. 如果未指定方向, 则为双向通道. 
  ``` go
  ch := make(chan int)
  ch <- v
  v := <-ch
  ```
* 默认情况下, 通道是不带缓冲区的. 发送端发送数据的同时必须要由接受端接受数据. 通道可以设置缓冲区, 通过make的第二个参数指定`ch := make(chan int, 100)`. 带缓冲的channel允许异步发送/接受数据. 不过缓冲区的大小是有限的, 所以还是必须有接受端来接受数据, 否则缓冲区满来, 接受方就不能发送数据.
* 遍历通道`v, ok := <-ch`. 当通道接受不到数据后`ok`为`false`, 这时channel可以使用`close(c)`来关闭

</details>

<details> <summary>Day45-49: 参考Go by Example阅读一些示例代码</summary>

工作中常写的是Python来跑任务, 但是近来越发觉得Python的性能不足, 因此考虑学习Go语言, 能很好地兼顾性能和开发效率, 并且谷歌的Syzkaller以及一众项目(包括未来的一些打算会需要性能和并发)都是使用Go语言编写, 因此有必要去掌握这门语言. 

学习过程中练习编写的代码: [Vancir/go-by-example](https://github.com/Vancir/go-by-example)

</details>

<details> <summary>Day50: 了解syzkaller并学习learn-go-with-tests</summary>

- [x] syzkaller的工作原理
  * `syz-manager`进程负责启动, 监控和重启管理的VM实例, 并在VM里启动一个`syz-fuzzer`进程. `syz-manager`负责corpus持久化和crash存储. 运行在具有稳定内核物理机层面
  * `syz-fuzzer`在不稳定的VM内部运行, 用于指导模糊测试进程(输入生产, 编译, 最小化等), 并通过RPC将触发新覆盖的输入发送回`syz-manager`. 它也会启动短暂的`syz-executor`进程
  * 每个`syz-executor`进程执行单个输入样例(syscalls序列), 它从`syz-fuzzer`处获取一个程序进行执行并返回执行结构. 它被设计得极尽简单(以避免干扰fuzz), 使用c++编写并编译成静态二进制文件, 使用共享内存进行通信.
- [x] learn go with tests
  * 编写测试: 
    * 程序需要在一个名为 xxx_test.go 的文件中编写
    * 测试函数的命名必须以单词 Test 开始
    * 测试函数只接受一个参数 t *testing.T
  * 常量可以提高应用程序的性能, 可以快速理解值的含义
  * 测试驱动(TDD):
    * 编写一个测试
    * 让编译通过
    * 运行测试，查看失败原因并检查错误消息是很有意义的
    * 编写足够的代码以使测试通过
    * 重构
  * 函数返回值使用(name string)更好, name的默认为零值, 只需要在函数内调用`return`即可, 并且这将显示在godoc内, 能使代码更加清晰.
  * 函数名称以小写字母开头。在 Go 中，公共函数以大写字母开始，私有函数以小写字母开头。我们不希望我们算法的内部结构暴露给外部，所以我们将这个功能私有化
  * 质疑测试的价值是非常重要的。测试并不是越多越好，而是尽可能的使你的代码更加健壮。太多的测试会增加维护成本，因为 维护每个测试都是需要成本的。
  * `reflect.DeepEqual`不是类型安全的, 当比较两个不同类型的时候会出问题

</details>

<details> <summary>Day51: 学习learn-go-with-tests</summary>

- [x] learn go with tests:
  * nil 是其他编程语言的 null。
  * 错误可以是 nil，因为返回类型是 error，这是一个接口。
  * 如果你看到一个函数，它接受参数或返回值的类型是接口，它们就可以是 nil。
  * 如果你尝试访问一个值为 nil 的值，它将会引发 运行时的 panic。这很糟糕！你应该确保你检查了 nil 的值。
  * map是引用类型, 可以是nil值, 但是为了避免nil指针异常错误, 应当使用`map[string]string{}`或`make(map[string]string)`来创建一个空map
  * 测试只测试**有效的行为**, 而不是所有的**实现细节**
  * 让它运作，使它正确，使它快速: 「运作」是通过测试，「正确」是重构代码，而「快速」是优化代码以使其快速运行。
* 阅读syzkaller源码: godep restore 将依赖包都安装好. 

</details>

<details> <summary>Day52: 学习angr使用的IR-VEX</summary>

* [pyvex](https://github.com/angr/pyvex): 介绍了pyvex的安装和基本的使用方法, 并且介绍了一些IR的知识. 不过不够详细, 只有简单的示例. 而且感觉VEX有点粗糙. 
* [Binary Analysis with angr](https://archive.fosdem.org/2017/schedule/event/valgrind_angr/attachments/slides/1797/export/events/attachments/valgrind_angr/slides/1797/slides.pdf): 使用vex来分析binary的一份ppt. 
* [https://github.com/angr/vex/blob/dev/pub/libvex_ir.h](https://github.com/angr/vex/blob/dev/pub/libvex_ir.h): 该代码内的注释详细得说明了vex.
  * IRSB: IR Super Blocks, 每个IRSB包括以下三样东西:
    1. a type environment, 指示IRSB中每个临时值的类型
    2. a list of statements, 代表代码
    3. a jump that exits from the end the IRSB. 基本块结尾的跳转
  * IRStmt(Statements): 表示带有副作用的操作
  * IRExpr(Expression): 表示无副作用的操作
  * guest state: 一块内存区域, 看描述理解是一块被VEX库控制的内存区域.
  * IRMark: 是个IR语句, 但不表示实际的代码, 它指示的是原始指令的地址和长度
  * ppIRFoo: 输出IRFoo的函数
  * eqIRFoo: IRFoos的结构对等谓词
  * deepCopyIRFoo: IRFoo的深拷贝, 会拷贝整个对象树, 所有的类型都有一个深拷贝函数
  * shallowCopyIRFoo, 浅拷贝, 只拷贝顶层对象

</details>

<details> <summary>Day53: 阅读《Go语言标准库》 </summary>
</details>

<details> <summary>Day54-57: 使用Go语言写一个HaboMalHunter</summary>

- [x] 使用golang读取配置信息
- [x] 使用golang执行外部命令
- [x] 增加检查是否使用UPX加壳
- [x] 使用file命令获取文件信息
- [x] 计算文件的Md5/Sha128/Sha256/SSdeep 
- [x] 支持提取文件的exif信息
- [x] 支持提取ELF文件的依赖库
- [x] 支持提取ELF文件的文件头信息

</details>

<details> <summary>Day58: 学习UW CSE501 静态分析课程 </summary>

* 优化选项: 
    * dead code elimination
    * partial redundancy elimination
    * function inlining
    * strength reduction
    * loop transformations
    * constant propagation
* special edge: 
    * back edge: 指向一个之前遍历过的block
    * critical edge: 既不是唯一离开source的边, 也不是唯一进入到target的边
* dataflow framework:  <G, L, F, M>
    * G = flow graph
    * L = (semi-)lattice
    * F/M = flow / transfer functions
- [x] reaching definition:
    * dataflow equations:
        * IN[b]	=	OUT[b1]	U	...	U	OUT[bn]	
        * OUT[b]	=	(IN[b]	-	KILL[b])	U	GEN[b]
        * IN[entry]	=	0000000	
    * solving equations:
    ```
    Input: flow graph (CFG)
    // boundary condition
    OUT[Entry] = 0...0
    // initial conditions
    for each basic block B other than entry
     OUT[B] = 0...0
    // iterate
    while (any out[] changes value) {
     for each basic block B other than entry {
     IN[B] = U (OUT[p]), for all predecessor block p of B
     OUT[B] = (IN[B] – KILL[B]) U GEN[B]
     }
    }
    ```
- [x] live variable
    * transfer function for live variable:
        * x = y + z
        * generates new live variable: USE[s] = {y, z}
        * kills previously live variable: DEF[s] = x
        * variables that were not killed are propagated: OUT[s] - DEF[s]
        * so: IN[s] = USE[s] | (OUT[s] - DEF[s])
    * setup
        * boundary condition: IN[exit] = None
        * initial conditions: IN[B] = None
        * meet operation: OUT[B] = | IN[Successors]
- [x] Must Reach: a definition D must reach a program point P if
    * D appears at least once along all paths that leads to P
    * D is not redefined along any path after the last appearance of D and before P
* constant propagation: lattice
    * undefined: variable has not been initialized
    * NAC: variable definitely has a value( we just don't known what )
    * meet rules:
        * constant & constant = constant (if equal)
        * constant & constant = NAC (if not equal)
        * constant & undefined = constant
        * constant & NAC = NAC
* maximal fixed point
* meet over paths: 可能是无穷个
</details>


<details> <summary>Day59: 学习UW CSE501 指针分析 </summary>

* 应用: 
    * 别名分析: 确定两个指针是否都指向相同的内存区域
    * 编译优化
    * 并行: 将串行代码转换成并行代码
    * shape analysis: 找到堆上数据结构的属性
    * 检测内存问题: 泄漏, 空指针引用等安全问题
* Point Language:
    * assume x and y are pointers
    * y = &x  -> means y points to x
    * y = x   -> means if x points to z then y points to z
    * *y = x  -> means if y points to z and z is a pointer, and if x points to w then z now points to w
    * y = *x  -> means if x points to z and z is a pointer, and if z points to w then y **not** points to w
    * points-to(x): set of variables that pointer variable x may point to 
* Andersen as graph closure
    * one node for each memory location
    * each node contains a points-to set
    * solve equations by computing transitive closure of graph, and add edges according to constraints
* worklist algorithm

    ```
W = { nodes with non-empty points-to sets }
while W is not empty {
    v = choose from W
    for each constraint v in x
        add edge x -> v, and add x to W if edge is new
    for each a in points-to(v) do {
        for each constraint p in *v
            add edge a -> p, and add a to W if edge is new
        for each constraint *v in q
            add edge q -> a, and add q to W if edge is new
    }
    for each edge v -> q do {
        points-to(q) = points-to(q) | points-to(v), and add q to W if points-to(q) changed
    }
}
    ```

</details>


<details> <summary>Day60-61: 二进制相似度聚类Golang实现 </summary>

- [x] 使用binding连接radare2
- [x] 获取程序的字符串信息
- [x] 对字符串进行Base64编码后计算SHA256
- [x] 通过radare2获取二进制的基本块数据
- [x] 使用capstone将二进制数据转换成汇编代码
- [x] 拿到汇编代码后, 生成基本块
- [ ] 拿到基本块后, 生成基本的控制流
- [x] 对基本块进行简单的符号化(去除偏移和立即数等)

</details>

<details> <summary>Day62-63: 学习MOBISEC安全课程</summary>

- [x] 04 - Intro to Android Architecture and Security

Binder是Android用于RPC和进程间通信的机制, Android利用Binder来将普通进程内调用的API转换到特权进程/服务实现的特权API. 

Android系统启动完毕后会广播一个带 ACTION_BOOT_COMPLETED action的 Intent, 因此app可以通过接收改该 Intent 来做开机启动, 也就可以用于持久化

SYSTEM_ALERT_WINDOW: 可以在其他APP上显示一个窗口, 这会导致许多UI界面的攻击, 比如UI混淆, 点击劫持, 钓鱼等. 

- [x] 05 - Real-World Android Apps

sharedUserId安全问题: 相同证书的APP可以申请使用相同的Linux User ID, 而具有相同的Linux User Id可以共享该ID的所有内容, 也可以访问彼此的内部隐私存储和其他组件等. 

- [x] 08 - Reverse Engineering

Android逆向方法流:

1. 大概了解app的功能: 模拟器里启动app, 观察初始的UI
2. 找到app的攻击面: 
    - 从入口点开始入手做攻击面分析
    - 检查app的各项组件(activities, broadcast, intent, receiver), 这些组件是否暴露给外部的app使用
    - 检查app如何与外部进行交互, 比如文件系统, 网络, 组件间通信等.
3. app如何跟网络端点交互
    - 寻找网络端点的IP, URL等. 虽然有可能经过混淆
    - 寻找网络相关API的调用代码
    - 在模拟器里运行并监视其网络活动.
4. app是如何存储隐私信息
    - 隐私信息包括有, 用户帐号证书, 用户隐私数据, 需要安全权限才能访问的数据等.
5. 检查某个函数是否存在滥用
    - app是怎么使用函数X的
    - app是否有安全地使用该函数
    - 攻击者该如何到达该函数?
</details>

<details> <summary>Day64: 学习LLVM</summary>

> 传送门: [LLVM Tutorial](https://llvm.org/docs/tutorial/)

</details>

<details> <summary>Day65: 编写脚本自动同步GoSSIP的微信推送归档到Github仓库</summary>

> 传送门: [GoSSIP-NewsBot](https://github.com/Vancir/GoSSIP-NewsBot)

理论上可以将任何微信公众号的推送定时更新到Github仓库里

</details>

<details> <summary>Day66: 阅读论文 FuzzGen: Automatic Fuzzer Generation</summary>

> 论文地址：[link](https://www.usenix.org/conference/usenixsecurity20/presentation/ispoglou)

> 项目地址：[link](https://github.com/HexHive/FuzzGen)

</details>

<details> <summary>Day67: 编写脚本检测PyPi包名抢注情况</summary>

> 项目地址：[link](https://github.com/Vancir/PyPi-Typosquatting-Graph)

![graph.png](https://raw.githubusercontent.com/Vancir/PyPi-Typosquatting-Graph/master/assets/graph.png)

红色点表示PyPi.org的Top4000的Python包, 且红色点越大表示其下载量越高, 绿色点则表示可疑的抢注包. 

图形主要分为三个层次, 最外层的Python包相对安全, 次外层的Python包有中等风险, 最内层的Python包有高的抢注风险

</details>

<details> <summary>Day68: 了解遗传算法并使用geatpy进行参数调优</summary>

> 源于朋友的一个问题, 朋友有一个疾病传染模型, 需要使用遗传算法进行参数调优

geatpy是一个国人维护的遗传算法工具箱, 具体的内容参考官方仓库里的 [demo](https://github.com/geatpy-dev/geatpy/tree/master/geatpy/demo)即可. 

1. 主要是确定自己的优化目标, 是进行多目标优化还是单目标优化, 来选择相应的算法模板. 
2. 然后确定自己的参数上下界, 参数之间的约束条件, 优化方向, 填入算法模板就可以了. 
3. 了解了下遗传算法的内容, 顺便也学习/重构了朋友的疾病传染模型.

</details>

<details> <summary>Day69-70: 编写macOS的内核扩展监控进程行为</summary>

> 仅列举编写时参考的资料, 目前可参考的公开资料很少, 除开参考以下内容外, 还需要更多的参考macOS SDK和开源的xnu的源码

1. [Apple's Technical Note TN2127](https://developer.apple.com/library/archive/technotes/tn2127/_index.html)
2. [Learn How to Build Your Own Utility to Monitor Malicious Behaviors of Malware on macOS](https://www.blackhat.com/us-18/arsenal.html#learn-how-to-build-your-own-utility-to-monitor-malicious-behaviors-of-malware-on-macos)
3. [Kemon: An Open-Source Pre and Post Callback-Based Framework for macOS Kernel Monitoring](https://www.blackhat.com/us-18/arsenal/schedule/#kemon-an-open-source-pre-and-post-callback-based-framework-for-macos-kernel-monitoring-12085)
4. [FireEye: Introducing Monitor.app for macOS](https://www.fireeye.com/blog/threat-research/2017/03/introducing_monitor.html)
5. [Objective-See](https://objective-see.com/blog.html)

</details>

<details> <summary>Day71: 参考xnu-qemu-arm64项目使用QEMU模拟iOS</summary>

> 传送门: [xnu-qemu-arm64](https://github.com/alephsecurity/xnu-qemu-arm64)

使用qemu+kvm模拟macOS目前算是资料较多的一方面了, 可以参考[Docker-OSX](https://github.com/sickcodes/Docker-OSX). 因为是写的dockerfile, 所以相当完善地记录了构建的整个过程, 熟悉qemu和黑苹果安装的话会很好理解. 

这次想来看这个项目是如何进行iOS的模拟的. 

* 准备材料: a **kernel image**, a **device tree**, a static **trust cache**, and **ramdisk** images
* 首先下载苹果官方给出的更新文件: [iOS 12.1 update file](http://updates-http.cdn-apple.com/2018FallFCS/fullrestores/091-91479/964118EC-D4BE-11E8-BC75-A45C715A3354/iPhone_5.5_12.1_16B92_Restore.ipsw) 它是一个zip文件可以直接解压

``` shell
$ unzip iPhone_5.5_12.1_16B92_Restore.ipsw
# 下载解压用的工具
$ git clone git@github.com:alephsecurity/xnu-qemu-arm64-tools.git
# 解码ASN1编码的内核映像
$ pip install pyasn1 # 脚本依赖pyasn1这个包
$ python xnu-qemu-arm64-tools/bootstrap_scripts/asn1kerneldecode.py kernelcache.release.n66 kernelcache.release.n66.asn1decoded
# 解码后还有一层lzss压缩, 继续解压
$ python xnu-qemu-arm64-tools/bootstrap_scripts/decompress_lzss.py kernelcache.release.n66.asn1decoded kernelcache.release.n66.out
# 获取device tree, 同样是ASN1编码, 用之前的工具解码即可.
$ python xnu-qemu-arm64-tools/bootstrap_scripts/asn1dtredecode.py Firmware/all_flash/DeviceTree.n66ap.im4p Firmware/all_flash/DeviceTree.n66ap.im4p.out
# 对于ramdisk同样进行ASN1解码
$ python3 xnu-qemu-arm64-tools/bootstrap_scripts/asn1rdskdecode.py ./048-32651-104.dmg ./048-32651-104.dmg.out
# 对ramdisk进行大小调整, 挂载和赋权
$ hdiutil resize -size 1.5G -imagekey diskimage-class=CRawDiskImage 048-32651-104.dmg.out
$ hdiutil attach -imagekey diskimage-class=CRawDiskImage 048-32651-104.dmg.out
$ sudo diskutil enableownership /Volumes/PeaceB16B92.arm64UpdateRamDisk/
# 挂载原来的映像
$ hdiutil attach ./048-31952-103.dmg 
# 为ramdisk内的dynamic loader cache创建空间并拷贝进去
$ sudo mkdir -p /Volumes/PeaceB16B92.arm64UpdateRamDisk/System/Library/Caches/com.apple.dyld/
$ sudo cp /Volumes/PeaceB16B92.N56N66OS/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64 /Volumes/PeaceB16B92.arm64UpdateRamDisk/System/Library/Caches/com.apple.dyld/
$ sudo chown root /Volumes/PeaceB16B92.arm64UpdateRamDisk/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
# 获取一些编译好的iOS工具, 包括bash
$ git clone https://github.com/jakeajames/rootlessJB
$ cd rootlessJB/rootlessJB/bootstrap/tars/
$ tar xvf iosbinpack.tar
$ sudo cp -R iosbinpack64 /Volumes/PeaceB16B92.arm64UpdateRamDisk/
$ cd -
# 配置launchd不要运行任何服务
$ sudo rm /Volumes/PeaceB16B92.arm64UpdateRamDisk/System/Library/LaunchDaemons/*
```

* 配置launchd运行bash: 创建 `/Volumes/PeaceB16B92.arm64UpdateRamDisk/System/Library/LaunchDaemons/bash.plist` 并写入以下内容

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>EnablePressuredExit</key>
        <false/>
        <key>Label</key>
        <string>com.apple.bash</string>
        <key>POSIXSpawnType</key>
        <string>Interactive</string>
        <key>ProgramArguments</key>
        <array>
                <string>/iosbinpack64/bin/bash</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
        <key>StandardErrorPath</key>
        <string>/dev/console</string>
        <key>StandardInPath</key>
        <string>/dev/console</string>
        <key>StandardOutPath</key>
        <string>/dev/console</string>
        <key>Umask</key>
        <integer>0</integer>
        <key>UserName</key>
        <string>root</string>
</dict>
</plist>
```

* 安装 **jtool** 然后将之前拷贝进去的预编译二进制进行信任.  

  ``` shell
  $ jtool --sig --ent /Volumes/PeaceB16B92.arm64UpdateRamDisk/iosbinpack64/bin/bash
  Blob at offset: 1308032 (10912 bytes) is an embedded signature
  Code Directory (10566 bytes)
                  Version:     20001
                  Flags:       none
                  CodeLimit:   0x13f580
                  Identifier:  /Users/jakejames/Desktop/jelbreks/multi_path/multi_path/iosbinpack64/bin/bash (0x58)
                  CDHash:      7ad4d4c517938b6fdc0f5241cd300d17fbb52418b1a188e357148f8369bacad1 (computed)
                  # of Hashes: 320 code + 5 special
                  Hashes @326 size: 32 Type: SHA-256
   Empty requirement set (12 bytes)
  Entitlements (279 bytes) :
  --
  <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
  <plist version="1.0">
  <dict>
      <key>platform-application</key>
      <true/>
      <key>com.apple.private.security.container-required</key>
      <false/>
  </dict>
  </plist>
  ```

* 将`CDHash`写入到`tchashes`内:

  ``` bash
  $ touch ./tchashes
  $ for filename in $(find /Volumes/PeaceB16B92.arm64UpdateRamDisk/iosbinpack64 -type f); do jtool --sig --ent $filename 2>/dev/null; done | grep CDHash | cut -d' ' -f6 | cut -c 1-40 >> ./tchashes
  ```

* 创建static trust cache blob

  ``` bash
  $ python3 xnu-qemu-arm64-tools/bootstrap_scripts/create_trustcache.py tchashes static_tc
  ```

* 将各个卷宗卸载掉

  ``` bash
  $ hdiutil detach /Volumes/PeaceB16B92.arm64UpdateRamDisk
  $ hdiutil detach /Volumes/PeaceB16B92.N56N66OS   
  ```

* 编译iOS定制过的QEMU

  ``` bash
  $ git clone git@github.com:alephsecurity/xnu-qemu-arm64.git
  $ cd xnu-qemu-arm64
  $ ./configure --target-list=aarch64-softmmu --disable-capstone --disable-pie --disable-slirp
  ```

* 使用QEMU将iOS虚拟机启动起来

  ``` bash
  $ ./xnu-qemu-arm64/aarch64-softmmu/qemu-system-aarch64 -M iPhone6splus-n66-s8000,kernel-filename=kernelcache.release.n66.out,dtb-filename=Firmware/all_flash/DeviceTree.n66ap.im4p.out,ramdisk-filename=048-32651-104.dmg.out,tc-filename=static_tc,kern-cmd-args="debug=0x8 kextlog=0xfff cpus=1 rd=md0 serial=2",xnu-ramfb=off -cpu max -m 6G -serial mon:stdio
  # 进入bash后, 修改PATH指向拷贝有预编译二进制的目录
  bash-4.4# export PATH=$PATH:/iosbinpack64/usr/bin:/iosbinpack64/bin:/iosbinpack64/usr/sbin:/iosbinpack64/sbin
  ```

</details>


<details> <summary>Day72: 参考macOS的网络流量监控代码</summary>

</details>

<details> <summary>Day73: 学习LLVM Pass的编写</summary>

参考资料: 
1. [LLVM官方资料: Writing an LLVM Pass](https://llvm.org/docs/WritingAnLLVMPass.html) 
2. [CS6120 Project3: Write an LLVM Pass](https://www.cs.cornell.edu/courses/cs6120/2019fa/project/3/): 同时也是一项公开的编译器课程
3. [Writng an LLVM Pass: 101 LLVM 2019 tutorial](https://llvm.org/devmtg/2019-10/slides/Warzynski-WritingAnLLVMPass.pdf)
4. [UG3 COMPILING TECHNIQUES 2019/2020](https://www.inf.ed.ac.uk/teaching/courses/ct/19-20/): 国外课程
5. [Github: banach-space/llvm-tutor](https://github.com/banach-space/llvm-tutor)
6. [Github: abenkhadra/llvm-pass-tutorial](https://github.com/abenkhadra/llvm-pass-tutorial): 简单的demo, 最下有给出其他的参考资料

- [x] 什么是LLVM Pass?
    * LLVM Pass意即LLVM的转换(transformations)和优化(optimizations)工作
    * 所有的LLVM Pass都继承于Pass类, 根据用途的不同, 可以继承的类有 ModulePass, CallGraphSCCPass, FunctionPass, or LoopPass, or RegionPass classes
- [x] LLVM PASS HelloWorld Demo
    * 首先下载LLVM的源代码, 我们的HelloWorld就在其源码的lib/Transforms/Hello下. 我当前的版本是10.0.1
    * 编辑lib/Transforms/Hello/CMakeLists.txt写入以下内容: 
      ``` cmake
        add_llvm_library(
          LLVMHello
          MODULE
          Hello.cpp
          PLUGIN_TOOL
          opt
          )
      ```
    * 编辑lib/Transforms/CMakeLists.txt加入`add_subdirectory(Hello)`
    * 以上是在配置CMake的编译环境, 接下来可以开始编写LLVM Pass.
    * 首先是引入头文件
      ``` c++
      #include "llvm/Pass.h"        // 编写PASS的头文件
      #include "llvm/IR/Function.h" // 操作函数用
      #include "llvm/Support/raw_ostream.h" // 输出信息用
      ```
    * 指定`using namespace llvm;` 因为引入的头文件里的函数存在于llvm命名空间里
    * `namespace {`指定匿名命名空间, 作用跟c的static类似, 能使得匿名空间内声明的代码仅在当前文件内可见
    * 在命名空间里声明我们的pass本身, 声明继承于FunctionPass, 以及重载FunctionPass的函数runOnFunction
      ``` c++
      namespace {
        // Hello - The first implementation, without getAnalysisUsage.
        struct Hello : public FunctionPass {
          static char ID; // Pass identification, replacement for typeid
          Hello() : FunctionPass(ID) {}

          bool runOnFunction(Function &F) override {
            ++HelloCounter;
            errs() << "Hello: ";
            errs().write_escaped(F.getName()) << '\n';
            return false;
          }
        };
      }
      ```
    * 初始化LLVM的Pass ID. LLVM使用ID的地址来标识一个pass, ID的值并不重要 `char Hello::ID = 0;`
    * 注册我们的Hello类: 第一个是命令行参数, 第二个是其参数释义
    ``` c++
    static RegisterPass<Hello> X("hello", "Hello World Pass",
                             false /* Only looks at CFG */,
                             false /* Analysis Pass */);
    ```
    * 注册pass到现有的分析流水线: 
      * PassManagerBuilder::EP_EarlyAsPossible 可以使得pass优先于所有优化pass前执行
      * PassManagerBuilder::EP_FullLinkTimeOptimizationLast 可以使得pass优先于所有链接时优化Pass前执行. 
    * 使用opt运行pass: `opt -load lib/LLVMHello.so -hello < hello.bc > /dev/null`
</details>

<details> <summary>Day74: 学习使用Ghidra进行逆向</summary>

> 参考资料: [hackaday-u](https://github.com/wrongbaud/hackaday-u)

参考资料是一个使用Ghidra进行逆向的教程, 但是里面有很多是讲逆向基础的, 所以就此略过, 仅关注其中跟Ghidra相关的部分. 

Ghidra只需要安装有JDK11后运行ghidraRun即可. 界面过于简陋了而且使用有点不方便, 工作需要创建一个工程, 然后点击CodeBrowser按纽(龙的标志)打开窗口, 然后再在窗口里点击上方菜单栏`File->Import File`将待分析的文件导入到工程里.  
打开后Ghidra进行分析, 然后左下角的`Symbol Tree`窗口里是的`Functions`就是各个函数了, 点击其中的函数, 就是相应的汇编代码及反编译的伪代码.

反编译的代码只能算能看了, 但还是有很大空间. 不过鼠标右键有切片的功能, 这就是Ghidra的优势之一了. 

* G: 跳转到地址/标签/表达式
* L: 重命名变量
* T: 定义数据类型
* B: 在整型之间快速转换 byte, word, dword, qword
* ': 在字符类型之间转换 char, string, unicode
* [: 创建数组
* P: 创建指针
* Shift+[: 创建结构体
* 导入C的头文件: File -> Parse C Source
* 交叉引用: References -> Show References to context
* S: 内存搜索值
* Ctrl+Shift+E: 搜索字符串

无头模式: 参考 [analyzeHeadlessREADME](https://ghidra.re/ghidra_docs/analyzeHeadlessREADME.html)

</details>

<details> <summary>Day75: 阅读AFL源码</summary>

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
  

</details>

<details> <summary>Day76: 阅读一篇开源库名称抢注检测的论文</summary>

> [SpellBound: Defending Against Package Typosquatting](https://arxiv.org/abs/2003.03471)

论文里对于名称抢注的判定有分以下几种情况, 称之为怀疑抢注的信号:

* Repeated characters: 比如request->reequest
* Omitted characters: 比如require-port->requires-port
* Swapped characters: 比如axois->axios
* Swapped words: 比如import-mysql->mysql-import
* Common typos: 这主要是一些肉眼的差异, 比如signqle->signale, lodash->1odash
* Version numbers: underscore.string->underscore.string-2

抢注包的攻击面也有进行讨论:

* Attacks against end-users: 直接影响终端用户, 执行恶意payload或者泄漏信息
* Attacks against developers using a package: 因为比如npm和pypi在安装时都是需要执行shell命令来进行配置和部署的. 但如果开发者使用root权限进行了系统全局的安装, 那么就可能以root身份执行恶意命令.
* Latent vulnerabilities: 直接镜像一个旧版本的开源库, 因为是镜像, 所以程序行为是一致的, 但是因为旧版本通常存在安全漏洞, 因此用这种方式来进行攻击. 
* Misattribution: 分流?


</details>

<details> <summary>Day77: 阅读FANS和Sys论文</summary>

* [Sys: a Static/Symbolic Tool for Finding Good Bugs in Good (Browser) Code](https://cseweb.ucsd.edu/~dstefan/pubs/brown:2020:sys.pdf)
* [FANS: Fuzzing Android Native System Services via Automated Interface Analysis](https://www.usenix.org/system/files/sec20fall_liu_prepub.pdf)

</details>

<details> <summary>Day78: 阅读两篇fuzzing论文</summary>

* [Detecting Critical Bugs in SMT Solvers Using Blackbox Mutational Fuzzing](https://numairmansur.github.io/STORM.pdf)
* [Fuzzing: Challenges and Reflections](https://www.computer.org/csdl/magazine/so/5555/01/09166552/1mgaKsMFDYA)

</details>


<details> <summary>Day79: 阅读fuzz深层状态空间探索的论文以及一些收藏文章</summary>

* [IJON: Exploring Deep State Spaces via Fuzzing](https://www.syssec.ruhr-uni-bochum.de/media/emma/veroeffentlichungen/2020/02/27/IJON-Oakland20.pdf)
* [Fuzzing Linux GUI/GTK Programs With American Fuzzy Lop (AFL) For Fun And Pr... You Get the Idea. Part One.](https://blog.hyperiongray.com/fuzzing-gtk-programs-with-american-fuzzy-lop-afl/)
* [Pigaios: A Tool for Diffing Source Codes against Binaries](https://docs.google.com/presentation/d/1ifvugStGL7Qc8xSFeYXp2MGQ6jQGOOMSolBrJy8kCMY/edit#slide=id.g4453e8add5_0_85)

</details>

<details> <summary>Day80-81: 阅读LLVM Cookbook</summary>

## 一些命令行

* opt指定单独的pass进行优化:
  * opt –passname -S demo.ll –o output.ll
  * pass的源码路径在llvm/test/Transforms下, 重要的转换pass:
    * instcombine 合并冗余指令
    * deadargelim 无用参数消除
    * mem2reg 优化内存访问(将局部变量从内存提升到寄存器)
    * adce 入侵式无用代码消除
    * bb-vectorize  基本块向量化
    * constprop 简单常量传播
    * dec: 无用代码消除
    * globaldce: 无用全局变量消除
    * globalopt: 全局变量优化
    * gvn: 全局变量编号
    * inline: 函数内联
    * licm: 循环常量代码外提
    * loop-unswitch 循环外提
    * lowerinvoke: invode指令lowering, 以支持不稳定的代码生成器
    * lowerswitch: switch指令lowering
    * memcpyopt: memcpy优化
    * simplicycfg: 简化CFG
    * sink: 代码提升
    * tailcallelim: 尾部函数调用消除
* 将C代码转换成LLVM IR:
  * clang -emit-llvm -S demo.c -o demo.ll
* 将LLVM IR转换成bitcode
  * llvm-as demo.ll -o demo.bc
* 将bitcode转换为目标平台汇编码
  * llc demo.bc -o demo.s
  * clang -S demo.bc -o demo.s -fomit-frame-pointer (clang默认不消除frame pointer, llc默认消除)
  * 加入-march=architecture参数能指定生成的目标架构
  * 加入-mcpu=cpu能指定目标CPU
  * 加入-regalloc=allocator能制定寄存器分配类型
* 将bitcode转回LLVM IR
  * llvm-dis demo.bc -o demo.ll
* 链接LLVM bitcode
  * llvm-link demo.bc demo2.bc -o output.bc
* lli执行bitcode, 当前架构存在JIT的话会用JIT执行否则用解释器. 
* 使用-cc1选项能指定clang只使用cc1编译器前端
* 输出AST: clang -cc1 demo.c -ast-dump
* 使用llgo来获取go语言转换的LLVM IR
  * llgo -dump demo.go
* DragonEgg是一个GCC插件, 能让GCC使用LLVM优化器和代码生成器
  * gcc testprog.c -S -O1 -o - -fplugin=./dragonegg.so
* opt可以指定-O设置优化级别, 使用--debug-pass=Structure可以查看在每个优化级别运行了哪些pass

## 编写LLVM Pass

### 0x01 编写makefile

在llvm lib/Transform目录下编写makefile文件, 指定llvm目录路径, 库名字, 标识模块为可加载

``` makefile
LEVEL = ../../..
LIBRARYNAME = FuncBlockCount
LOADABLE_MODULE = 1
include $(LEVEL)/Makefile.common
```

### 0x02 编写pass代码

``` c++
#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"

// 引入llvm命名空间以使用其中的函数
using namespace llvm;
namespace {
  // 声明Pass
  struct FuncBlockCount : public FunctionPass {
    static char ID; // 声明Pass标识符, 会被LLVM用作识别Pass
    FuncBlockCount() : FunctionPass(ID) {}
    // 实现run函数
    bool runOnFunction(Function &F) override {
      errs()<< "Function "<< F.getName()<< '\n';
      return false;
    }
  };
}
// 初始化Pass ID
char FuncBlockCount::ID = 0;
// 注册Pass, 填写名称和命令行参数
static RegisterPass<FuncBlockCount> X("funcblockcount", 
                                  		"Function Block Count", false, false);
```

使用opt运行新的pass: 

* opt -load (path_to_so_file)/demo.so -funcblockcount demo.ll

</details>

<details> <summary>Day82-83: 学习NLP里的命名实体识别模型(NER) </summary>

命名实体识别是NLP的一个基础任务, 简单说就是标定词性. 传统的实现方式都是用的LSTM+CRF, CRF是条件随机场的英文缩写. 当然也有用BiLSTM的, 因为是双向,所以能兼顾上下文的语义信息. 

Google在19年发布的BERT模型也能运用在NER里, 能够帮助提升性能, 也是一个新的实现方案. 

NLP有一个框架名为spaCy, 能运用在工业级场景里, 它的底层也大多用的CPython进行编写. 我主要参考它仓库里的example进行训练, 详情参考: [train_ner.py](https://github.com/explosion/spacy/blob/master/examples/training/train_ner.py)

大致的使用方法就是使用内置的`ner`流水线, 然后训练的时候禁用掉其他内置的流水线, 通过多次的迭代训练. 当然除此外还有一些其他的代码, 比如分割训练集/测试集, 对模型进行性能评估之类的一些代码, 在官方的示例中没有体现, 需要自己去实现. 

</details>

<details> <summary>Day84: 学习字符串的几种相似度算法的代码</summary>

> 参考项目地址: [python-string-similarity](https://github.com/luozhouyang/python-string-similarity)

* Method of four russians 四个俄罗斯人算法
* Levenshtein 编辑距离: 将一个字符串转化成另一个字符串所需要编辑(插入/删除/替换)的最少次数, 使用Wagner-Fischer算法实现, 空间复杂度为O(m), 时间复杂度为O(m*n)
* Normalized Levenshtein: 在Levenshtein基础上除以最长的字符串长度, 以进行归一化. 
* Weighted Levenshtein: 在Levenshtein基础上对不同字符的编辑设置了去不同的权重, 常用于OCR识别, 比如将P替换成R的成本比将P替换成M的成本要低, 因此P跟R是更为相似的. 也可以用于键盘输入的自动纠正, 比如键盘上相邻字符的替换成本更低. 
* Damerau-Levenshtein: 在Levenshtein基础上增加了`交换`操作, 将相邻的两个字符交换位置.
* Optimal String Alignment: 在Damerau–Levenshtein基础上增加了限制条件: no substring is edited more than once, 区别在于对交换操作增加了一个递归.  
* Jaro-Winkler: 最早用于记录重复链接的检测, 适用于短小的字符串比如人名以及检测错别字. 是Damerau-Levenshtein的变种, 其认为相隔距离远的2个字符交换的重要性要比相邻字符的要大.
* Longest Common Subsequence: 最长公共子序列问题在于找到2个或更多序列公共的最长序列. 与查找子字符串不同, 子序列不需要是连续的, 被用于git diff来记录变动. 字符串X(长度n)和Y(长度m)的LCS距离为`n+m-2|LCS(X, Y)|`, 其最小为0, 最大为n+m. 当编辑仅允许插入和删除, 或者替换的成本为插入删除成本的2倍时, LCS距离等同于编辑距离. 通常使用动态规划来实现, 时间复杂度和空间复杂度均为O(n\*m). 也有新的算法能实现O(log(m)\*log(n))的时间复杂度, 但是空间复杂度的要求是O(m\*n^2)
* Metric Longest Common Subsequence: 计算公式 `1 - |LCS(s1, s2)| / max(|s1|, |s2|)`
* N-Gram: 使用\n附加字符来增加首字符的权重. 
* Shingle (n-gram) based algorithms: 将字符串分割成长度为n的序列然后进行处理, 除开直接计算字符串的距离外, 对于大数据机, 还可以对所有字符串进行预处理再计算距离.
  * Q-Gram: 两个字符串的距离为其profile(每个n-gram出现的次数)差异的L1范数: `SUM( |V1_i - V2_i| )`. Q-gram距离是编辑距离的下界, 但可以在O(m+n)的时间复杂度内完成计算. 
  * Cosine similarity: 两个字符串向量表示的夹角的余弦值: `V1 . V2 / (|V1| * |V2|)`, 距离则为`1-cosine`
  * Jaccard index: 将每个字符串都视为n-gram的集合, `|V1 inter V2| / |V1 union V2|`, 距离则为`1-index`
  * Sorensen-Dice coefficient: 类似于jaccard index, 计算公式为: `2 * |V1 inter V2| / (|V1| + |V2|)`, 距离为`1-similarity`
  * Overlap coefficient: 类似jaccard和sorensen-dice: `|V1 inter V2| / Min(|V1|,|V2|)`, 倾向于产生更高的结果.
* SIFT4: 受JaroWinkler和LCS启发的通用字符串距离算法, 希望尽可能地接近人类对弦距离的感知. 

</details>

<details> <summary>Day85: 阅读Accelerated C++第5,6章</summary>

* 迭代vector:
  ``` c++
  for (vector<Student_info>::const_iterator iter = students.begin(); 
    iter != students.end(); ++iter) { 
      cout << iter->name << endl;
      cout << (*iter).name << endl;
  }
  ```
* `copy(bottom.begin(), bottom.end(), back_inserter(ret));`中copy(begin, end, out), 指定拷贝的起始, 终点以及输出的目标. 而back_inserter()在其参数作为目标的时候, 能将内容附加到其参数后, 也就是拷贝到ret的末尾. 切要注意, 不能使用`copy(bottom.begin(), bottom.end(), ret.end())`
* `transform(begin, end, out, func)`前三个参数是迭代器, 第四个参数是函数, begin和end用来指定元素的范围, 而out指定转换后元素的目标存储, 而func则是对应的转换函数, 会用于begin和end指定范围内的各个元素. 
* `accumulate(v.begin(), v.end(), 0.0)`以0为起点, 将v的值全部累加起来. 
* `remove_copy(begin, end, out, value)`, 从容器内移除begin和end指定的内容, 并拷贝其中与value不相等的部分到out
* `partition(begin, end, func)`会对begin, end指定范围进行排布, 满足func为True的排在前面, False的排在后面. 然后返回bounds, 也就是True和False的边界. 这个排布是不稳定的, 可能会打乱其内部的排列顺序, 因此也可以使用`stable_partition`

</details>

<details> <summary>Day86-87: 阅读Accelerated C++第7及后续章节</summary>

* map的迭代器是pair类型, 且pair类型均是const的, 对于pair类型其有first和second两个成员, 应该是对应于python的tuple.
* 一个模版类声明的示例:
  ``` c++
  template <class T> class Vec { 
  public:
    typedef T* iterator; 
    typedef const T* const_iterator; 
    typedef size_t size_type; 
    typedef T value_type;

    Vec() { create(); } 
    explicit Vec(size_type n, const T& t = T()) { create(n, t); }

    Vec(const Vec& v) { create(v.begin(), v.end()); } 
    Vec& operator=(const Vec&); 
    ~Vec() { uncreate(); }

    T& operator[](size_type i) { return data[i]; } 
    const T& operator[](size_type i) const { return data[i]; }

    void push_back(const T& t) { 
      if (avail == limit) 
        grow(); 
      unchecked_append(t); 
    }

    size_type size() const { return avail - data; }

    iterator begin() { return data; } 
    const_iterator begin() const { return data; }
    iterator end() { return avail; } 
    const_iterator end() const { return avail; } 
  private:
    iterator data; // first element in the Vec 
    iterator avail; // (one past) the last element in the Vec 
    iterator limit; // (one past) the allocated memory

    // facilities for memory allocation 
    allocator<T> alloc; // object to handle memory allocation

    // allocate and initialize the underlying array 
    void create(); 
    void create(size_type, const T&); 
    void create(const_iterator, const_iterator);

    // destroy the elements in the array and free the memory 
    void uncreate();

    // support functions for push_back 
    void grow(); 
    void unchecked_append(const T&);

  };
  ```
* 对于类继承的改写函数使用virtual指定虚函数

</details>

<details> <summary>Day88: 阅读LLVM Essentials第1章</summary>

* 对于LLVM IR有以下解释: 
  * ModuleID: 指定LLVM模块ID. 一个LLVM模块包含输入文件的完整内容, 由函数, 全局变量, 外部函数原型, 符号表等组成. 
  * datalayout字符串可以指明字节序(e表示小端)以及文件类型(e表示elf, o表示mach-o)
  * IR里所有的全局变量用@作为前缀, 局部变量用%作为前缀
  * LLVM将全局变量视为指针, 因此对指针进行解引用需要使用load指令, 存储值需要使用store质量. 
  * `%1 = value`是寄存器变量, `%2 = alloca i32`是分配在栈上的变量
  * 函数名前的@表明其在全局是可见的.
  * LLVM使用三地址码且是SSA格式
  * ident指明模块和编译器版本. 
* LLVM工具
  * clang -emit-llvm -c add.c
  * llvm-as add.ll –o add.bc
  * llvm-dis add.bc –o add.ll
  * llvm-link main.bc add.bc -o output.bc
  * lli output.bc
  * llc output.bc –o output.s

</details>

<details> <summary>Day89: 阅读LLVM Essentials第2章</summary>

书里使用的应该是LLVM 3.8的版本, 目前LLVM已经更新到11, 且macos通过homebrew安装的10.0.1版本其`--system-libs`的xml2存在问题. 所以会有一些不适用的情况. 尽管代码发生了很大的变化, 但好在很多思路是大致一样的. 

* LLVM提供了Module()来创建模块, 创建模块需要指定其name和context
* 编译时需要引入LLVM的头文件, 使用`llvm-config --cxxflags --ldflags --system-libs --libs core`
* IRBuilder类用于生成LLVM IR. 
* llvm:Function用于生成函数, llvm::FunctionType()用于关联函数的返回值类型
* 对于生成的Function可以使用verifyFunction()来检查是否正确
* Module类的getOrInsertGlobal()函数可以用于创建全局变量
* Linkage: 指定链接类型
* phi指令用于分支条件情况, 对于不同分支的基本块使用phi指令来确定具体使用哪一个分支的结果(因为IR是SSA形式)

简单的LLVM 10示例代码

``` c++
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"
#include <stdio.h>

using namespace llvm;

int main(int argc, char *argv[]) {
  LLVMContext Context;
  Module *Mod = new Module("MyModule", Context);
  raw_fd_ostream r(fileno(stdout), false);
  verifyModule(*Mod, &r);

  FILE *my_mod = fopen("MyModule.bc", "w+");
  raw_fd_ostream bitcodeWriter(fileno(my_mod), true);
  WriteBitcodeToFile(*Mod, bitcodeWriter);
  delete Mod;
  return 0;
}
```

</details>

<details> <summary>Day90: 阅读LLVM Essentials第3,4章</summary>

* getelementptr指令用于获取地址, 本身并不访问内存, 只是做地址的计算
* load指令用于读取内存内容, store指令用于写入内容到内存
* insertelement将标量插入到向量中去, 其接受三个参数, 依次是响亮类型, 插入的标量值, 插入索引位置
* extractelement从向量里读出标量. 
* doInitialization: 用于初始化. runOn{Passtype}一般是针对Passtype的处理函数. doFinalization则是最后的结尾清理环境用的
* 编写LLVM Pass需要在`lib/Transforms`下创建目录, 并在其内创建Makefile大概如下:
  ``` makefile
  LEVEL = ../../.. 
  LIBRARYNAME = FnNamePrint 
  LOADABLE_MODULE = 1 
  include $(LEVEL)/Makefile.common
  ```
* 一个打印函数名的pass如下:
  ``` c++
  #include "llvm/Pass.h" 
  #include "llvm/IR/Function.h" 
  #include "llvm/Support/raw_ostream.h"

  using namespace llvm;

  namespace {

  struct FnNamePrint: public FunctionPass { 
    static char ID; 
    FnNamePrint () : FunctionPass(ID) {} 
    bool runOnFunction(Function &F) override { 
      errs() << "Function " << F.getName() << '\n'; 
      return false; 
      } 
    };
  }

  char FnNamePrint::ID = 0;
  static RegisterPass< FnNamePrint > X("funcnameprint","Function Name Print", false, false);
  ```
  最后两行是向pass manager注册当前pass
* 给opt提供–debug-pass=Structure选项可以查看pass运行的情况
* getAnalysisUsage可以指定pass之间的依赖关系
  * AnalysisUsage::addRequired<>方法设定pass的依赖关系, 指定的pass会先于当前pass执行
  * AnalysisUsage:addRequiredTransitive<>指定多个依赖组成分析链条
  * AnalysisUsage::addPreserved<>指定暂时保存某个pass的结果以避免重复计算. 

</details>

<details> <summary>Day91: 阅读LLVM Essentials第5,6章</summary>

* dominator tree: 支配树, 当所有通向节点n的路径也一定都通过节点d时, 我们称节点d支配节点n, 表示为d->n, 对于所有基本块构成的也就是支配树. 
* DAG: directed acyclic graph, 用于代码生成的一个有向无环图. 
* 代码生成: 将IR转化成SelectionDAG然后进行多阶段优化: DAG组合, 合法化, 指令选择, 指令调度等, 最后分配寄存器生成机器码. 
* SelectionDAGBuilder接口用于创建对应IR指令的DAG节点

</details>

<details> <summary>Day92-94: 阅读LLVM官方文档</summary>

这些是我在阅读官方文档时觉得比较重要的资料, 当然一些比如设置环境Get Started之类的文档略过

* [Developing LLVM passes out of source](https://releases.llvm.org/11.0.0/docs/CMake.html#developing-llvm-passes-out-of-source)
  * 示例的LLVM Pass的结构目录如下
    ``` shell
    <project dir>/
        |
        CMakeLists.txt
        <pass name>/
            |
            CMakeLists.txt
            Pass.cpp
            ...
    ```
  * <project dir>/CMakeLists.txt 内容
    ``` shell 
    find_package(LLVM REQUIRED CONFIG)

    add_definitions(${LLVM_DEFINITIONS})
    include_directories(${LLVM_INCLUDE_DIRS})

    add_subdirectory(<pass name>)
    ```
  * <project dir>/<pass name>/CMakeLists.txt: `add_library(LLVMPassname MODULE Pass.cpp)`
  * 如果想更好地整合进LLVM源码里(通过add_llvm_library), 可以使用以下方式:
  * 将以下内容添加到<project dir>/CMakeLists.txt文件里去(在find_package(LLVM ...)后)
    ``` shell
    list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
    include(AddLLVM)
    ```
  * 修改<project dir>/<pass name>/CMakeLists.txt为以下:
    ``` shell
    add_llvm_library(LLVMPassname MODULE
      Pass.cpp
      )
    ```
  * 集合进LLVM源码:
    1. 拷贝<pass name>文件夹到<LLVM root>/lib/Transform
    2. 添加add_subdirectory(<pass name>)到<LLVM root>/lib/Transform/CMakeLists.txt


* [LLVM’s Analysis and Transform Passes](https://releases.llvm.org/11.0.0/docs/Passes.html): 对各个pass的用途进行了介绍, 也有很多分析的实现, 可以作为样例去学习
* [LLVM Programmer’s Manual](https://releases.llvm.org/11.0.0/docs/ProgrammersManual.html)
  * formatv用于格式化字符串输出
  * 使用assert进行断言: `assert(isPhysReg(R) && "All virt regs should have been allocated already.");`
  * 使用llvm_unreachable函数指定控制流不会到达的分支

</details>

<details> <summary>Day95: 编写词法分析器</summary>

</details>

<details> <summary>Day96: 编写LLVM Pass</summary>

</details>


<details> <summary>Day97: 阅读论文QSYM混合模糊测试</summary>

## 摘要

混合模糊测试在CGC中被证明有效, 但同时现有的混合执行存在性能瓶颈, 且难以运用于复杂大型软件, QSYM应运而生. 

QSYM通过动态二进制翻译技术, 将本地执行和符号执行紧密结合在一起. 此外QSYM放宽了传统混合执行引擎的健壮性要求以提高性能, 但利用更高效的Fuzzer进行验证, 在一些方面比如约束求解和修剪无用基本块提高了性能.

## 简介

传统模糊测试能快速探索输入空间, 但无法很好地进入深层空间, 而混合执行则擅长深层空间的状态但难以解决复杂的约束. 混合模糊测试则是将两者结合在一起, 而作者认为混合执行引擎的性能瓶颈时制约混合模糊测试的主要因素, 而论文的解决性能瓶颈的方法就是将符号执行的部分通过动态二进制翻译(DBT)的方案转变成本地执行, 同时相对现有的混合执行引擎而言, 也能实现更细粒度的指令级别执行. 此外也降低了健壮性的一些要求使其性能更高, 能应用于大规模测试. 

## 动机: 性能瓶颈

### P1. 符号执行开销

论文探讨了符号执行低效的原因: 首先符号执行对IR的依赖降低了性能, 其次针对IR的优化器没有充分地进行优化(限制了优化空间), 特别是将程序翻译成基本块级别IR这部分. 最后是没法跳过不涉及符号执行的那部分指令. 

IR能够降低原型实现的复杂度, 但同时也带来了额外的开销. 比如amd64架构指令是CISC, 而IR是RISC, 在转换过程中一条机器指令就会被转化成多条IR, 从实验结果来看, Angr使用的VEX IR则平均膨胀了4.69倍. 

IR优化器有自己的一些优化策略, 比如不涉及符号变量的基本块就不进行符号执行, 这确实能提高性能但不充分, 因为对于含有符号变量的基本块, 从真实软件测试来看, 只有约30%的指令需要符号执行. 也就意味着指令级别的符号执行能减少不必要的符号执行开销. 但现有的混合执行引擎因为IR缓存策略, 常常以基本块为单位转换成IR以降低缓存的成本, 因此没有从基本块级别上做优化. 

论文则是以此出发, 移除了IR转换, 增加实现复杂性, 和尽可能最小化符号执行的使用. 

### P2. 低效的快照

传统混合执行引擎使用快照来减少重新执行目标程序的开销, 但对于一些混合执行引擎来说快照机制是必要的, 例如Driller. 传统符号执行需要快照来保存分支的探索状态, 而对于混合模糊测试中的混合符号执行引擎, 则是从从Fuzzer处拿测试样例, 而这些样例的路径很可能是不同的, 因此也就没有必要使用快照来保存分支状态. 

同时快照机制需要频繁地与外部环境比如文件系统和内存管理系统交互, 但当进程通过fork族的系统调用创建子进程时, 内核不再维护其状态, 因此混合执行引擎需要自行维护状态. 

快照机制还会有其他的问题, 论文中则对重复的混合执行进行优化, 移除了快照机制, 取而代之使用具体执行. 

### P3. 低效不灵活的健壮性分析

混合执行会试图收集完整的约束来保证健壮性, 确保满足约束的输入能引导到预期路径. 然而计算完整约束的代价可能非常昂贵. 比如一些密码学或解压的函数, 强求完整约束会使得其没法探索其他有趣的代码. 此外过度约束也会带来计算开销. 

论文里则是收集不完整的部分约束, 并针对过度约束情况仅求解其部分约束. 

## 设计

QSYM的设计架构如下图所示: 

![qsym-architecture.png](https://i.loli.net/2020/10/26/t6fYoxhIrCbGq9s.png)

### 优化混合执行引擎

使用了四种技术来对混合执行引擎进行优化. 

1. 指令级别的符号执行: 使用DBT在单个进程允许本地和符号执行, 使得其模式的切换开销非常小
2. 只求解相关约束: 只求解跟目标分支相关的约束并产生新的测试样例. 传统符号执行引擎例如S2E和Driller会逐步求解约束, 并关注于通过前段执行解决当前执行中约束的最新部分, 而这对于没有初始输入可供探索的符号执行器而言是非常有效的. 但并不适用于混合执行. QSYM相比Driller在输出测试样例能够仅修改跟分支相关的约束. 但这里对QSYM的输出没有很好的解释. 
3. 更多使用重新执行而非快照: 重新执行程序到达特定路径状态的开销可能比快照恢复要高的多, 但当QSYM的混合执行引擎变快, 快照恢复的开销会高于重新执行. 
4. 具体的外部环境: 不再对外部环境进行建模而是与具体的外部环境进行交互, 将外部环境视为黑盒给予具体值运行, 这是处理那些无法模拟的函数的常用手段, 但很难适用于给予fork的符号执行, 因为这会打破进程边界. QSYM做了折衷的方案, 损失一定的健壮性, 通过Fuzzer来快速检查及丢弃测试用例来停止进一步的分析. 

### 优化求解器

混合执行容易遇到过度求解的问题. QSYM通过求解最后一条路径约束来达到提速的目的, 这样有两点考虑, 一是乐观地认为最后一条约束通常具有比较简单的形式, 能很高效地进行约束求解(作者也有考虑过求unsat_core的补集, 但其也是计算高昂), 二是求解最后一条约束, 能保证后续的约束求解结果也一定满足这最后一条到底该分支的约束.

### 修剪基本块

重复代码生成的约束对于实际测试中查找新的代码覆盖率没有帮助, 并且有的时候会因为复杂的基本块带来的约束限制了进一步的探索. 

QSYM会在运行时测量每一个基本块执行的频率, 并选择重复的基本块进行修剪. 如果基本块执行的过于频繁, 则会放弃从该基本块生成进一步的约束. 当然除开那些不引入任何新符号表达式的常量指令组成的基本块, 例如x86的mov指令以及使用常量对指令进行移位/屏蔽. 

QSYM利用2的指数来计算基本块的频率, 这可以快速地制止过于频繁的基本块, 但同时也带来了过度修剪的问题, QSYM采用了两种方式来解决过度修剪: 基本块组合和上下文敏感性. 

基本块组合是将多个基本块视为一个组合, 比如8个基本块视为一个组合, 那么当这个组合执行了8次之后, 其频率才加一, 也就是一种缓和的策略. 

上下文敏感则是为了对在不同上下文运行的同一基本块做区分. 比如两个strcmp(), 其上下文是不同的, 故这两次调用需要视为不同的基本块进行频率计数. QSYM会维护当前执行的调用堆栈, 并计算其哈希来区分不同的上下文. 

</details>

<details> <summary>Day98: 阅读论文SAVIOR-Bug驱动的混合模糊测试</summary>

## 简介

在混合执行有了较大进展的背景下, 针对于漏洞检测场景混合执行的效果并不乐观, 而作者主要认为有两个原因: 首先盲目选择种子用于混合执行以及不加重点地关注所有的代码, 其次就是混合模糊测试注重于让测试过程继续下去而非去检查内部的漏洞缺陷. 于是作者提出了SAVIOR, 它会优先考虑种子的混合执行并验证执行路径上所有易受攻击的程序位置. 

说白了, SAVIOR想解决混合模糊测试里乱选种子的行为, 并且希望以Bug为导向去选择种子. 那么具体的策略就是, 在测试前, SAVIOR会静态分析源代码并标记潜在的易受攻击位置. 此外, SAVIOR会计算每个分支可达的基本块集合, 在动态测试期间, SAVIOR优先考虑可以访问更重要分支的种子进行混合执行. 

除开上述说的能加快漏洞检测速度, SAVIOR还会验证混合执行引擎遍历过路径上标记的漏洞. 具体就是, SAVIOR综合了各个漏洞路径上的约束, 如果该约束在当前路径条件下可以满足, 那么SAVIOR就会求解该约束以构造输入进行测试. 否则SAVIOR会证明该漏洞在此路径上不可行. 

## 设计

### Bug驱动优先级

Bug驱动的关键是找到一个方法去评估某个种子在混合执行时能暴露出的漏洞数量, 这个评估取决于两个先决条件:

* R1 - 种子执行完后评估可访问代码区域的方法
* R2 - 量化代码块中漏洞数量的指标

针对R1, SAVIOR结合动静态分析去评估种子的可探索代码区域. 在编译期间, SAVIOR会从每个分支静态地计算可达的基本块集合, 在运行期间, SAVIOR则会在种子的执行路径上标记未探索的分支, 以及计算这些分支可访问的基本块集合. 

针对R2, SAVIOR则是利用UBSan来标注待测程序里的三种潜在的错误类型. 然后将每个代码区域中的标签计算为R2的定量指标. 同时SAVIOR也采用了一些过滤方法来删除UBSan的无用标签. 

### Bug导向验证

该技术可以确保在到达了漏洞函数路径上能进行可靠的漏洞检测. 从模糊测试处给定种子, SAVIOR会将其执行起来并沿执行路径提取各个漏洞标签. 之后SAVIOR会检查当前路径条件下的可满足性, 满足即漏洞有效. 

## 实现

SAVIOR由多个部分组成: 构建在Clang+LLVM之上的工具链, 基于AFL的Fuzzer, KLEE移植过来的混合执行引擎和负责编排的协调器. 

SAVIOR的编译工具链可用于漏洞标记, 控制流的可达性分析以及不同组件的构建. 

漏洞标记则是基于UBSan, 当然UBSan有一些不如意的地方, SAVIOR对其进行了一些调整. 

可达性分析用于计算CFG中每个基本快可到达的漏洞标签的数量. 它分为两个阶段, 第一步是类似SVF方法去构建过程间CFG, 其首先会为每个函数构建过程内CFG再通过调用关系建立过程间的关系. 为了解决间接调用, 算法会反复执行Andersen的指针分析, 以防止SAVIOR丢失间接调用的函数别名信息, 也使得优先级划分不会漏算漏洞标签数量. 此外通过检查CFG, SAVIOR还提取了基本块和子对象之间的边, 以便后续在协调器的进一步使用. 第二步则是计算过程间CFG中每个基本块可到达的代码区域, 并计算这些区域中UBSan标记的数量, 以此作为该基本块的优先级指标. 

组件构建则是去编译三个binary: 一个用于fuzzer的binary, 一个用于协调器的SAVIOR-binary, 一个则是用于混合执行引擎的LLVM bitcode. 

协调器则是用于挑选优先级高的种子, 以及一些后续处理.  混合执行引擎则采取了一些策略去解决约束问题. 

</details>

<details> <summary>Day99: 阅读论文Angora通过搜索策略提高性能</summary>

## 简介

Angora的主要目标是无需借助符号执行的情况下, 求解路径约束以提高分支覆盖率, 为达到该目标, 其引入了四种关键技术: 字节级污点跟踪, 上下文敏感的分支计数, 梯度下降法以及输入长度探索. 

* 上下文敏感的分支覆盖: AFL使用上下文无关的分支覆盖率来近似认为程序状态, 但实验表明上下文敏感能让Angora探索更广泛的状态
* 字节级别的污点跟踪: 大多数的路径约束其实只跟输入里的少量字节相关, 因此Angora回去跟踪哪些字节跟对应的路径约束相关, 仅变异这些相关的字节而非整个输入. 
* 梯度下降法: Angora使用梯度下降法来解决路径约束. 
* 类型/形状推断: 输入中的许多字节经常会作为整体共同作用于一个值, 比如4字节用作32位有符号整数, 为了让梯度下降能有效地搜索, Angora设法找到上述的组并推断其类型. 
* 输入长度探索: 程序有时对输入有长度的要求, 符号执行和梯度下降都不能告诉Fuzzer何时应当增加输入的长度, Angora则会检测输入是否会影响到路径约束, 并适时增加输入长度. 

## 设计

### 上下文敏感的分支覆盖

将分支定义为(prev, cur, context), prev和cur是当前分支前后基本块ID, 而context则是h(stack), h代表哈希函数, stack则是调用堆栈状态. 但用堆栈表示上下文的话, 遇到递归就会出现重复很多次. 因此h这个哈希函数仅将每个调用点计算一次来规避递归带来的重复问题. 

### 字节级别的污点跟踪

Angora将程序的每个变量与一个污点标签tx做关联, tx表示可能流入x的输入中字节偏移量. 当然这里的污点标签需要满足快速的Insert/Find/Union操作, 因此作者通过构建二叉树来优化了时空效率. 

### 梯度下降法和类型/形状推断

使用梯度下降法得到局部最优解作为路径约束的解, 而对于字节而言, 简单的应用梯度下降是合适的, 但对于多个字节组成的单个值, 在计算梯度的时候会出现问题, 所以作者必须解决类型推断的问题. 

为了解决该问题, Angora需要确定 (1) 输入里哪些字节被组合成单个值 (2) 判断这单个值其类型. 论文里将(1)称为形状推断(shape inference), 将(2)成为类型推断(type inference)

* shape inference: 初识时所有字节都视为独立的. 在污点分析期间, 当一条指令读取字节序列输入给变量, 且该字节序列长度与原始类型的大小匹配(例如1,2,4,8字节), 则将这些字节序列标记为同一个值
* type inference: Angora通过指令的语义作为依据来判断类型. 比如是一个对有符号整数进行运算的指令, Angora则将其操作数认作有符号整数, 如果一个数被同时用做有符号和无符号时, Angora则默认认为其是无符号. 当然推断不出来的话, Angora也没辙了.

### 输入长度探索

污点跟踪期间, Angora会在read类函数调用时, 将目的内存地址和对应输入的字节偏移关联起来. Angora也会将read函数调用的返回值用特殊标签进行标记. 如果在条件语句中使用到了返回值同时又不满足约束条件了, 那么Angora就会增加输入的长度以满足分支的约束. 

</details>


<details> <summary>Day100: 阅读论文SymCC通过编译而非解释进行符号执行</summary>

作者认为符号执行中的执行器是性能的主要瓶颈, 而目前大多数的符号执行引擎都会将被测程序转化成IR(比如LLVM bitcode), 然后在IR基础上符号执行, 而作者解决该瓶颈的方案就是将符号处理编译到二目标程序中去, 最终得到无需外部解释即可执行的二进制文件, 在运行目标程序的同时, 跟踪各个符号表达式, 使得在符号推理的同时又能保证程序的运行速度. 

符号执行的早期就有多个引擎采用了该思路, 但它们都受到了以下两点的影响:

1. 源代码的插装会使得其绑定到某个固定的编程语言上, 而SymCC则是处理IR, 与语言无关
2. 在完整的编程语言集上实现该目的可能非常困难, 而IR相比完整编程语言集而言小得多. 

SymCC基于LLVM构建, 首先获取待测程序的LLVM bitcode, 然后将其编译成具有符号执行功能的二进制文件, 而在程序的每个分支点, 都会生成一个偏离当前执行路径的输入. 换句话说就是SymCC能产生混合执行的Binary. 

</details>

<details> <summary>Day101: 阅读论文PANGOLIN和了解污点分析技术</summary>

</details>

<details> <summary>Day102-103: 阅读论文libdft污点分析技术</summary>

动态数据流跟踪(DFT)用于处理程序在运行期间传递的标记并跟踪感兴趣的数据, 我们以下图示例代码为例, 其主要分为以下三个方面: 

![example.png](https://i.loli.net/2020/11/03/W7ogFcmwEhk8R1u.png)

* Data Source: source是程序或者一个内存位置, 通常在执行函数或系统调用之后, 就会引入相关数据, 比如Figure 1中我们把文件定义为source, 那么read函数就会继而标记data和pass
* Data Tracking: 程序运行期间会跟踪标记数据的复制情况和更改情况. 比如Figure 1中标记了data变量, 那么在接下来的while循环里, csum与data数据相关, 就会继而标记csum. 而(b)中, pass跟phash有数据相关, 而phash跟authorized存在控制相关, 这就是一种间接的控制流依赖. 
* Data Sink: sink也是程序或内存位置, 通常可以在sink点处对标记数据进行检查, 比如不允许数据存在某些内存区域或者函数参数的检验. 比如在Figure 1中, 写入文件作为sink, write函数则对csum进行了相关操作. 

DFT需要额外的空间保存数据标签, 另外, 程序本身也需要使用标签传播逻辑和数据标签进行扩展, 并且分别检查source和sink的逻辑, 为此使用插桩代码来实现. 代码插桩可以通过静态注入方式(在源代码开发/编译/加载过程)实现, 也可以使用虚拟化或动态二进制插桩(DBI)实现. 无论静态/动态方法实现插桩, 都需要将程序的数据和标签进行关联, 并注入逻辑以在source处声明标签, 然后根据程序语义定义的数据依赖性来传播它们, 最终检查sink是否存在标记数据. 

</details>

<details> <summary>Day104: 简略阅读四篇污点分析论文</summary>

</details>

<details> <summary>Day105: 学习MIT公开课Data Tracking</summary>

> 视频地址: [21. Data Tracking](https://www.youtube.com/watch?v=WG5UbMrUiLU&ab_channel=MITOpenCourseWare)

视频以Android的TaintDroid为例介绍污点分析.
* sources: 敏感数据的来源, 比如传感器数据, 联系人信息, IMEI这些都是敏感数据
* sink: 不希望敏感数据到达的地方, 比如网络. 
* taintdroid使用32位向量表示taint, 用于跟踪32个taint sources
* 污点的传播方式:
  * mov dst, src: 污点直接从src传递到dst
  * union: 比如两个污染源影响同一个变量
  * native method: 一些native的方法比如arraycopy也能传播污点
  * IPC消息
  * 文件
* 需要标记的污点: 局部变量, 函数参数, 对象实例的成员, 静态类型的成员, 数组
* 污点的难题: 性能开销大, 误报多, x86指令复杂,很难准确建模
* implicit flow: 隐式的控制流去影响某些变量的值以达到传播的目的, PC被污染

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

<details>
<summary>2020/8/11 CTF选手说：在玄武实验室工作始终怎样的体验</summary>

> 来自玄武实验室微信公众号当日推送: [link](https://mp.weixin.qq.com/s/EoLuRrJVmlQRYhpm6cib3w)

</details>

## 关于X-Man夏令营

非常感谢[赛宁网安](http://www.cyberpeace.cn/), [诸葛建伟老师](https://netsec.ccert.edu.cn/chs/people/zhugejw/)和[陈启安教授](https://information.xmu.edu.cn/info/1018/3156.htm)的帮助才让我有幸成为第一期X-Man夏令营的成员. 我也是在X-Man夏令营里认识了[A7um](https://github.com/A7um), [iromise](https://github.com/iromise), [40huo](https://github.com/40huo)等一众大佬. 就我同期的X-Man夏令营学员们, 几乎都投身于国内的安全事业, 如今学员们遍地开花, 也是诸葛老师非常欣慰看见的吧. 

## 关于作者

从初入社会到如今的这半年多时间里, 我找到了生活工作和学习的节奏, 我并没有选择急于去钻研技术, 而是阅读了更多的非技术类书籍, 这教导了我为人处世的经验, 在北京站稳了脚跟, 顺利从刚毕业的懵懂小生过渡到现在略有成熟的青年. 而如今我要展开脚步, 去追求梦想的工作了, 所以我创建了该项目, 既是对自我的激励监督, 也是向分享我的学习历程.

玄武实验室对于国内安全从业人员的吸引力, 就如同谷歌对广大程序员的吸引一般, 我渴望着得到玄武实验室的工作. 而我认识的[A7um](https://github.com/A7um)也在玄武实验室, A7um是我初学安全时仰慕的偶像之一, 我期待着能与玄武实验室里才华横溢的大佬们一起共事研究. 
