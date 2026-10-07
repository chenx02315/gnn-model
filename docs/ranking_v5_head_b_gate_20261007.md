# B端v5合成门禁：CPU前向与梯度通过，保留CUDA警告

复用B现有Python3.11.2 / PyTorch2.5.1+cu124环境；31项依赖逐项与原lock一致。没有安装依赖、启动Docker或访问真实TRAIN/BLIND/VALIDATION数据、图、checkpoint。两份已固定SHA的源文件经STDIN仅在内存执行；未部署文件、未写远端产物。旧v5 design的pending记录保留为历史状态，新合同为v2。

实际执行一次，exit0、零重试，全部合成断言通过：

- CPU float64前向loss与纯Python参考在1e-12内一致。
- 最佳正例的梯度是负，第10负例的梯度是正，其余非活动负例是0，与解析sigmoid公式在1e-12内一致。
- 负例少于10时，天然命中家族loss与所有梯度为0，不冒充训练信号。

`autograd.grad`只对人工分数求导，没有模型拟合或optimizer step；不能把它称为训练实验效果。真实训练器仍未引用v5。

## 资源和警告

耗时1.149秒，进程峰值RSS412598272 bytes（约393.5MiB），单worker/线程1/interop线程1。保持8GiB地址空间硬限制、1GiB RSS观察停止阈值；RSS不是硬上限。无GPU计算请求，CUDA_VISIBLE_DEVICES为空。

PyTorch autograd发出了CUDA初始化警告：cudaGetDeviceCount返回Error2 out of memory。所有CPU数值断言仍完成，但**不能将环境报告成无警告，也不能断言警告原因已经确定**。随后的只读容量快照：六块GPU显存已用18/18/18/18/411/18MiB，主机available约983553MiB；这不能证明先前瞬态状态，亦不能证明RLIMIT_AS就是原因。未提高限制、屏蔽警告、重复实验或操作其他用户进程。

原始日志含JSON与完整warning，SHA `96e49e67ae197316b84504a7a6292221565e952131c8b654e35e358be2773d05`。Git仅收小型receipt/source/合同，远端环境与历史目录不改。

## 当前状态与下一节点

CPU实际计算门禁已过；CUDA警告保持caveat。独立agent代码/证据复核尚未执行，不将本地自动校验冒充独立复核。已准备好审核包：隔离objective、合成torch入口、bounded STDIN bootstrap、source SHA、固定依赖、raw receipt、纯Python测试与完整回归。

本次自动衔接完成了“环境恢复→源码绑定→实际torch合成检查→warning只读排查→数值/资源回执→本地回归→封存”。下一步是独立复核及单目标变更对照的预注册；本门禁不自动放行新18项真实训练、调参、BLIND或LSF/Tessent。不得因为合成梯度方向正确就宣称拟合困难电路、迁移或ATPG成本已经改善。

本地11项focused通过、完整765项测试/25skip/0fail/error/exit0（83.829秒），完整日志SHA `1b8d2f7a1e710c1e2cf0a5504789e1973bafa4c7acd3bcffa414eef86331a805`。CPU实际门禁与本地回归分开记账，跳过测试不冒充其他Linux门禁。受控对照设计保存在 `contracts/ranking_v5_head_controlled_comparison_design_v1.json`，审核请求为 `data/manifests/ranking_v5_head_review_request_20261007.json`，两者都不是PASS或执行放行。
