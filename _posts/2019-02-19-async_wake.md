---
layout:     post
title:      async_wake
subtitle:   async_wake利用 
date:       2019-02-19
author:     GK
header-img: img/home-bg-o.jpg
catalog:    true
tags:
    - async_wake
    - macOS
---

# 前置利用

proc_pidlistuptrs寻找并返回kqueue中的用户态指针，传入k * 8 + 7大小的user_buff，内核会kalloc相同大小的kernel_buff，若找到的指针数量大于k，实际只拷贝k * 8长度到kernel_buff，最终copyout到user_buff的却有k * 8 + 7。由于kalloc时不会清零，会有7个字节泄露。

首先填充足够多的kevent使得proc_pidlistuptrs由于user_buff不够大，返回内容被截断。然后构造不同大小的OOL_PORTS数组，将自己的task port发送给自己，再立刻释放并申请相同大小的user_buff
调用proc_pidlistuptrs拿到7个字节的泄漏，此时出现次数最多的值就是自己task port的kaddr。虽然只有7个字节，整数以小端字节序保存且内核指针以0xffffff开头，所以能恢复出完整的指针。

CVE-2017-13865

# 目标tfp0

由于是port UAF，我们的目标是port所在的内存被free后能kalloc成我们控制的payload。port有专用的zone叫ipc.ports，port所在的内存若想挪做他用必须通过gc回收后再申请。苹果所有设备的zone map是384MB，当zone map 95% full的时候，gc会被触发，此时需要有足够多的内存回收才能祈祷不被杀死。

在kalloc.1024 zone上通过mach_msg持有大约150MB左右的内存，防止与利用需要操纵的kalloc.4096 zone冲突。同时申请一堆port耗尽ipc.ports zone上已经存在的内存，迫使内核拿出完整的页分割以达到某些页上只有我们申请的port的目的。这样在free这些port后，一个整页都free了，保证gc时能被成功回收。选最后一小部分的port中的一个为target_port，满足以下要求：target_port的地址，整个fake_ipc_port和整个fake_task的范围在mach_msg_header_t和MAX_TRAILER_SIZE之间，即必须是能控制内容的部分。target_port用来触发IOSurface UAF，同时free其他同时申请的port。释放之前kalloc.1024 zone上持有的内存，然后每次1MB缓慢地通过mach_msg申请kalloc.4096 zone上大约200MB的内存，其中根据target_port的地址构造了IKOT_TASK类型的fake_ipc_port和fake_task的payload。150MB + 200MB将触发gc，此时期许target_port所在的整页被回收且此页被用于payload的kalloc。通过检查target_port的ip_context并与payload中预设的值比较，就能知道哪次mach_msg的payload成功的占据了target_port所在的页。

此前payload将fake_task的bsd_info和fake_ipc_port的的ip_context对齐,所以先设置ip_context为kaddr - offsetof(struct proc, p_pid)再调用pid_for_task就能读取kaddr上的int值。

离tfp0还差kernel_task的vm_map和自己task port的ipc_space，从我们自己的task开始遍历task双链表，找到p_pid为0的内核task，并取得vm_map。释放target port所在页的内存，再次大量mach_msg构造好的fake_kernel_task和fake_ipc_port，以期许payload再次占据target_port所在的页。成功之后就拥有了tfp0。

当payload被释放后访问tfp0将崩溃，因此需要构造一个稳定的tfp0。发送一个msg给一个新创建的final_port，偷走final_port的ipc_kmsg queue中的唯一ipc_kmsg pointer，我们就拥有了一块kbuff用以构建fake_kernel_task。将final_port改造成IKOT_TASK类型且指向fake_kernel_task，同时把receive right变成send right。final_port就是稳定的tfp0。

CVE-2017-13861

# macOS提权

proc->p_ucred.cr_uid = 0

proc->p_ucred.cr_ruid = 0

proc->p_ucred.cr_svuid = 0

[实现](https://github.com/Gentle-Knife/async_wake)

# 另一种利用方案

[v0rtex](https://siguza.github.io/v0rtex/)

# 参考

<https://bugs.chromium.org/p/project-zero/issues/detail?id=1417>
<http://blog.pangu.io/iosurfacerootuserclient-port-uaf>
