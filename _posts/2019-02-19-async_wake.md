---
layout:     post
title:      async_wake
subtitle:   async_wake 在 macOS 上的利用 
date:       2019-02-19
author:     GK
header-img: img/home-bg-o.jpg
catalog:    true
tags:
    - async_wake
    - macOS
    - mach port
---

# 前置利用

&nbsp;proc_pidlistuptrs 函数返回 kqueue 中的用户态指针，参数传入 k * 8 + 7 长度的 user_buff，内核会 kalloc 相同长度的 kernel_buff。若找到的指针数量大于 k，实际只拷贝 k * 8 长度到 kernel_buff，最终 copyout 到 user_buff 的长度却有 k * 8 + 7。kalloc 时不会清零，所以会有7个字节泄露。

首先填充足够多的 kevent，目的是使得 proc_pidlistuptrs 函数需要返回的内容太长被截断。然后构造不同长度的 OOL_PORTS 数组，将目标 mach port 发送给自己，再传入相同长度减 1 的 user_buff参数，调用 proc_pidlistuptrs 函数拿到 7 个字节的泄漏，泄露的 7 个字节中重复次数最多的值就是目标 mach port 的内核地址。虽然只有 7 个字节，但是 macOS /IOS 上整数是以小端字节序保存且内核地址以 0xffffff 开头，固能恢复出完整的地址。

CVE-2017-13865

# 目标tfp0

漏洞类型是 mach port UAF，我们的目标是 mach port 所在的内存被 free 后能替换成我们控制的 payload。mach port 有专用的 zone 叫做 ipc.ports，mach port 所在的内存若想挪做他用必须先通过 gc 回收 mach port 所在的整页，此类手法有个专用术语叫做 cross zone attack。macOS /IOS 的 zone map 是 384 MB，当 zone map 95% full 的时候，gc 将会被触发，此时占用内存最多的某些进程需要有足够多的内存回收才能祈祷不被系统杀死。

在 kalloc.1024 zone 上通过 mach_msg 先持有大约 150 MB 左右的内存，避开利用需要操纵的 kalloc.4096 zone。然后申请足够多的 mach port 耗尽 ipc.ports zone 上现有的内存，迫使内核拿出完整的页分割成 struct ipc_port 的大小，以期望在这些页上只有我们申请的 mach port。这样在 free 所有的 mach port 后，这些整页大概率都是 free 的状态，gc 时能被成功回收。从存在于这些整页的 mach port 中选一个作为 target_port，满足以下要求：target_port 的内核地址、构造的 fake struct ipc_port 和构造的 fake struct task 的范围在 4096 大小的 mach_msg 之内，具体是在 mach_msg_header_t 和 MAX_TRAILER_SIZE 之间，即必须是能控制内容的部分。target_port 用来触发 IOSurface UAF，同时 free 其它所有申请的 mach port。接着 free 之前 kalloc.1024 zone 上持有的内存，再缓慢地每次 1 MB 地申请 kalloc.4096 zone 上的内存，总共申请大约 200 MB 的 mach_msg 用以被 payload 填充。其中每个 4096 大小的 payload 是这样构造的：前置利用拿到 target_port 的内核地址，根据该地址计算出在一整页上的偏移，在此偏移上构造 IKOT_TASK 类型的 fake struct ipc_port 和 对应的 fake struct task。150 MB + 200 MB 的 zone map 会触发 gc，此时期望 target_port 所在的整页被 gc 回收，且此页正好被某个 4096 大小的 payload 重新申请到。通过检查 target_port 的 ip_context 值与每个 payload 中预设的值比较，就能知道哪次 mach_msg 的 payload 成功的占据了 target_port 所在的页。

payload 将 fake struct task 的 bsd_info 和 fake struct ipc_port 的 ip_context 对齐，通过设置 ip_context 的值为 kaddr - offsetof(struct proc, p_pid)，再调用 pid_for_task 的返回值就是 kaddr 地址上的int值。这是经典的通过误用 pid_for_task 达到任意地址读的手法。 

距离成功构造 tfp0 还差 kernel_task 的 vm_map 和自己 task port 所在的 ipc_space。我们已经能够任意地址读，并且通过前置利用能够拿到自己 task port 所在的内核地址。以我们自己的 task 作为切入点遍历所有 task 的双链表，找到 p_pid 为 0 的 kernel_task，并取得 kernel_task 的 vm_map。通过自己的 task port 同时能读取对应的 ipc_space。再次释放 target_port 所在整页的内存，只需要 free 此页上的 mach_msg 即可。最后再次申请大量 4096 大小的 mach_msg， 只不过此次的 payload 填充上预先读到的 vm_map 和 ipc_space，以期许某个 payload 再次占据 target_port 所在的页。此时成功地构造出 tfp0。

当 payload 被 free 后继续访问 tfp0 将引发崩溃，因此需要构造一个稳定的 tfp0。发送一个 mach_msg 给新创建的 final_port，偷走 final_port 的 ipc_kmsg queue 中唯一的 ipc_kmsg pointer，故意造成内核的内存泄露，我们就拥有了一块内存用以构造 fake kernel_task。将 final_port 改造成 IKOT_TASK 类型且指向 fake kernel_task，同时把 receive right 变成 send right。final_port 就被构造稳定的 tfp0。

CVE-2017-13861

# macOS提权

>proc->p_ucred.cr_uid = 0
>proc->p_ucred.cr_ruid = 0
>proc->p_ucred.cr_svuid = 0

[macOS 版本实现](https://github.com/Gentle-Knife/async_wake)

# 没有前置利用的利用方式

[v0rtex](https://siguza.github.io/v0rtex/)

# 参考

<https://bugs.chromium.org/p/project-zero/issues/detail?id=1417>
<http://blog.pangu.io/iosurfacerootuserclient-port-uaf>
