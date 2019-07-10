---
layout:     post
title:      task_for_pid和processor_set_tasks
subtitle:   task_for_pid和processor_set_tasks
date:       2019-03-06
author:     GK
header-img: img/home-bg-o.jpg
catalog:    true
tags:
    - task_for_pid
    - processor_set_tasks
---

&emsp;&emsp;task_for_pid 能拿到指定 pid 的 task port 的 send right，等于完全控制了该 task，是 code injection 的必要条件，调用需要 root 权限。

&emsp;&emsp;task_for_pid 已经添加了 patch 防止拿到 kernel task(0) port 的 send right。在 macOS 上被 taskgated(10.10) 或者 AMFI(10.11+) 管理，弹出消息框用于验证 dev tools debug 的权限。在 IOS 上需要 task_for_pid-allow entitlement 才能调用。

&emsp;&emsp;于是找到了 processor_set_tasks 作为替代，调用同样需要 root 权限。macOS上 能拿到所有 task port 的 send right，包括 kernel task。IOS 上能拿到除了 kernel task 以外所有 task port 的 send right。

![ipc](/img/post-processor_set_tasks.jpg)

&emsp;&emsp;毫无意外最终被 patch 了。macOS 10.11+ 同样需要 entitlement 才能使用。

&emsp;&emsp;最后附上 [code injection sample](http://newosxbook.com/src.jl?tree=listings&file=inject.c)。