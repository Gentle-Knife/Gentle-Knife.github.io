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

task_for_pid能拿到指定pid的task port的send right，等于完全控制了该task，是code injection的必要条件，需要root权限。

task_for_pid已经添加了patch防止拿到kernel task(0) port的send right。在macOS上被taskgated(10.10)或者AMFI(10.11+)管理，弹出消息框用于验证dev tools debug的权限。在ios上需要task_for_pid-allow entitlement才能使用。

于是找到了processor_set_tasks另辟蹊径，同样需要root权限。macOS上能拿到所有task port的send right，包括kernel task。ios上能拿到除了kernel task以外所有task port的send right。

![ipc](/img/post-processor_set_tasks.jpg)

毫无意外最终被patch了。macOS 10.11+同样需要entitlement才能使用。

最后附上[code injection sample](http://newosxbook.com/src.jl?tree=listings&file=inject.c)。