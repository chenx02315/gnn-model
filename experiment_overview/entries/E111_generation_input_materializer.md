# E111：把实际输入准备接到固定执行配方

## 本轮完成的是代码与Mock，不是服务器数据

实现一个输入准备组件，复用已有anchored读写、流式复制、树摘要与独占发布原语。没有重新创建一套runner，没有访问A/B或读取实际库/TSDB；测试只读仓库中的既有E85/E88/E93元数据及两份小Tcl模板。

后续正式运行时，它负责新建一个专属E108根目录，发布精确派生Tcl、库、共同故障全集/映射/清单，并为每次Tessent调用建立独立TSDB副本。库路径、logs、prereq、TSDB等位置按E108原配方，Tcl会自己创建的result目录及tool log不能提前创建。

## 接线顺序

增量Tessent的E86 binding只有翻译提交后才能取得，所以不能先准备M/F的Tessent槽来“顺便”创建翻译目录。新增prepare_translation只从本instance已经登记的run/freeze及精确翻译槽推导目标prereq，不转换、不克隆TSDB、不启动进程。后续M/F物化只能复用本instance对应的目录，拒绝外来目录或错误翻译绑定。

准备回调只是可信controller传入的操作许可声明，不是真实用户授权，也不扣launch次数。Tessent同时携带semantic binding SHA与effective envelope SHA；翻译准备只有semantic SHA，effective为null，不把两类摘要混称，也不把小翻译引用当作MTFI文件摘要。

## 审查中修复的问题

- 最初可以用分母20的假freeze准备E88真实分母的输入。现在两个API在IO前均强制N与manifest SHA匹配E88元数据：AES 71216、SPI 10418；这些数字不是新测的覆盖率。
- 共享文件及目标副本复核增加owned父目录inode检查，不能只看相同内容SHA。
- TSDB复制后、目标读回前后增加named-root归属检查。同内容但目录已被替换，也必须失败并使该实例不可复用。
- 明确IO阶段异常保留半成品并使对象失效；单纯验证/许可拒绝在IO前退出、不修改状态。它不是并发隔离或全局额度机制，实际controller仍须唯一串行拥有该对象。

## 验证与边界

24项专项、180项选定本地Mock/协议回归及独立复核通过，覆盖完整48次TSDB准备、30次翻译prereq准备、错N/manifest、同内容换根、输入变化、ROOT碰撞、失败不可复用、流式sink及精确size/O_EXCL。使用的是Mock命名空间，不是48份真实TSDB。

与E108/旧materializer的45项联合检查中，有5项Linux实体IO测试在Windows跳过；不能把这些skip当作物理门禁通过。后续实际Linux IO、最新输入身份、环境、进程监督、唯一持久intent和完整controller仍需完成。

更新：用户已明确答复“授权上述整包，全部门禁通过后自动执行”，实际授权另存prospective_acquisition_authorization_e111_20261026.json。原提案PENDING保留为当时快照，不当作当前权限。现在无需重复请求同一整包，但本组件通过仍不是完整执行链通过；继续整合并独立复核，在所有门禁通过前不启动采集。尚未访问A端，14小时与调用额度未开始消耗；仍不训练或访问BLIND/B端。
