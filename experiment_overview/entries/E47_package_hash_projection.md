# E47：正式package的来源绑定已实际读回

## 结论

一次B端限定读取成功，完整manifest原字节2374B，其SHA与E42历史封存一致：

`66c6776c033c87c2b41fa6cdeb05852e650eb1fe5173600fae2f0d2a8907eafc`

这不再只是旧记录里的声明，而是本次已观察精确文件的读回。正式package绑定的候选receipt SHA是：

`48c164e99e653c1d00dbf8e7655447e2ffc09c9519c63b7191dff9a151b7456d`

candidate_space和normalized_measurements的两个哈希也与既有封存一致。下次找到候选receipt副本时必须先匹配这个完整原字节SHA，不能靠同名、配置相同或多数版本猜测正式来源。

## 读了什么，没读什么

只打开E46实际观察到的一个manifest；完整字节用于SHA与JSON语法扫描。只解码字段名称，以及schema_version、candidate_receipt/candidate_space/normalized_measurements三个哈希值；未解码、评价或输出其余oracle/质量结果值，也没有跟随任何声明路径。不可把这描述成“根本没读manifest字节”，也不可描述成“整份质量内容已解封”。

逐组件nofollow打开目录，文件必须普通、单硬链接、大小<=128KiB，FD和最终路径身份前后一致。先通过完整SHA再投影。1GiB/单worker/20秒CPU/120秒超时/64KiB每流/零自动重试，不写远端，不访问受保护目录。

实际调用exit0、传输和响应接受；投影SHA为`6c13c196cfb6ef02bbbb95a7bde64f9f151bf8a1e5ebd81142ff68ebb51960e9`，见[小型投影](../../data/manifests/ranking_v6_e47_projection_20261017_r1.json)。0.502秒是元数据操作耗时，不是ATPG耗时。

## 测试和失败保留

初版10项本地单元测试中4项ERROR：Windows缺少Linux的O_DIRECTORY/O_NOFOLLOW常量，发生在mock FD测试中，没有调用远端或读取真实文件。只修正测试setup，为缺少的常量提供mock值；实际Linux读取器未改。修后10项全部执行通过，无跳过。这些mock本身不是Linux执行证明。

相关完整回归596项，590执行、6条件跳过、0失败/错误，64.454秒。独立代码/解析器/范围复核通过后才执行实际一次投影。原有回归中的模拟timeout回执不是本轮真实B端失败，不计作额外远端调用。

## 还缺什么

候选receipt内容及它绑定的source_provenance仍未恢复，24份正式源文件版本、完整搜索计费、候选全集和执行前冻结仍未认证；训练没有放行。继续只读定位两份元数据/具备可验证来源的副本，不重跑ATPG、不增加电路、不更换目标指标。
