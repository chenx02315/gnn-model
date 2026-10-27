# E131：获授权的目标版本文档核验

## 目的与实际授权

目标是核实Tessent2021.2对EQ归属与统计展开的规则，为已有H/F报告的计数口径对账提供版本适用依据；不是再采集ATPG，不是修改D95合同。

用户在E131文档核验包请求后明确回复“授权”。实际记录 contracts/coverage_semantics_documentation_authorization_e131_20261027.json，SHA-256 f50274633de10dc743808dcfa7f87a473d30a4c4b8614cffe55770182ba0aa59；提案SHA-256 3d1d88125bcc9256be70a18c893d5e4070da025fdd9dd379e50e2709553bff5e。原文用UTF-8码点核验，不能以自动目标消息代替实际授权。

## 硬边界

A端安装根 /cad/mentor/tessent2021_2 下doc、docs、help、share/doc、share/help，目录深度≤2、条目总≤200，元数据响应≤64KiB。符号链接不得借安装根内bin、license、用户或设计路径绕过docs-only范围。

最多2次只读SSH（盘点1次、导出1次），零自动重试；每次≤60秒协作期限，首次实际访问起总≤300秒，512MiB采样边界。只导出经真实metadata复核的最多3个候选、正文总≤32MiB，完整SHA校验后才能分析。没有Tessent/ATPG/LSF/B/BLIND/训练或历史实验报告访问，也不重置旧实验时钟。

## 条件复核设计

先冻结并独立复核盘点精确包和导出固定源码/参数协议，再启动第一次调用。真实metadata后由主代理审查exact候选ID、logical/resolved文档路径及完整metadata SHA，然后在剩余300秒窗口内导出；这一选择复核是主代理实际事后审查，不冒称独立代理预先看过真实选择。若窗口不足、范围不符或没有合适文档，不续期、不扩大路径、不启工具。

## 文档读取准备

依赖定位工具当前不可用，已只读核对本机已有Codex运行时：Python包含pypdf/pdfplumber，Poppler提供pdftoppm/pdfinfo/pdftotext，无需安装软件。若获得PDF，按PDF检查流程只提取并渲染相关规则页和版本页，不批量展开全手册，不更改原PDF。文档正文留本地staging，不上传Git；Git只收代码、版本/页码记录及SHA。

当前授权/协议设计独立核验通过。第一版13项专项及166项相关旧回归通过，但主代理和独立复核共同发现一个执行前阻断：特殊文件类型原先只在打开后拒绝，不能保证metadata-only。正在聚焦补上打开前的普通文件/目录检查与设备、FIFO、socket反例；原review_request_r1保留为修复前快照，不能作为放行回执。

截至此快照尚无实际目录盘点或导出结果，5分钟访问窗口未启动，规则语义仍未核实。只有修复版重冻摘要并独立复核通过后才开始读取。

## 实际执行结果：盘点失败，未导出、未重试

修复版已通过180项联合回归，独立复核14项专项、Python3.6语法及metadata/export各15模块inert装载通过。放行仅覆盖精确metadata包和固定export协议，不冒称实际文件选择已独立复核。

唯一实际metadata调用返回989B，SHA-256 6d16731f4e125fdd43949c93f6a2efbb58216e5f03b114bff4ed98310708b8ba。A端身份与安装根真实快照已返回，但capture_complete=false，error为TypeError / DOCUMENT_PROBE_FAILED，scan=null；因此没有可接受候选，没有文档正文导出，也不能声称安装目录没有手册。远端观察耗时0.107768秒，采样峰值13197312字节；writes/child/Tessent/training均0。SSH退出0只说明传输返回，不代表盘点通过；transport没有独立远端终止证明。

本地交互进程已退出，无第二次访问。本包零自动重试，不把预留export额度改成第二次metadata，不变更首次时钟。原响应、intent、transport与start保存在本地staging的v6_e131_documentation_probe_20261027_r1；小型索引为data/manifests/ranking_v6_e131_actual_failure_20261027_r1.json。

## 兼容性候选原因与下一步

当前源码scan_metadata使用os.scandir(fd)。[Python官方版本说明](https://docs.python.org/3/library/os.html#os.scandir)表明Unix整数文件描述符支持从3.7才加入；本地Python3.13的Mock与AST3.6语法检查不能证明3.6运行时API兼容。这个风险与实际TypeError及root已核实/scan未完成吻合，但因为真实错误包未含精确堆栈，不能把候选原因写成已经由现场traceback唯一确认。

仅在新文件准备本地兼容组件与受限流式扫描测试，保留本次已执行源码不改写；不会使用os.listdir(fd)一次性装入未知目录，也不切换工作目录或扩大到安装根外。新远端文档包需要单独明确授权，规则核验/旧D95合同/ATPG/训练仍未放行。
