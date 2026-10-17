# E46：确认package manifest的精确位置

目的：在E45真实列出的四个子目录各列一层指定元数据名称，不按猜测打开文件或遍历整个B端。

一次实际调用exit0，回执通过。四处直接条目分别2、7、2、2个；发现：

- `/ssd/cjc/gnn_model_runtime_v2_input_stage_98efbd4f_20261002/runtime_training_package_v2_r1/runtime_training_package_manifest_v2.json`
- 环境根`inputs`下还有一个`runtime_training_package_v2`子目录；尚未进入。
- 两份源码根`data`下没有选中的元数据名称；不能推成整个B端缺失。

stdout SHA：`5ff186aec432050cedc04230d2d13e2f072074d2b41083fa7233927072967010`。只是名称与nofollow stat，不是已读取manifest或认证正式源版本。没有进入依赖、结果、checkpoint或受保护目录。

6项针对性测试通过；相关回归586项，580实际执行、6条件跳过，0失败/错误，66.623秒。独立复核通过后才实际执行，包括纯mock逐组件FD检查；mock不是Linux正向运行证明。实际B端运行只证明本次限定目录定位成功。

下一步E47只打开这个已观察manifest：完整原始字节用于固定SHA核对，随后只解码schema与3个来源哈希；其他值仅做JSON结构扫描，不解码/评估/导出。候选receipt和逐源provenance仍未恢复，不读质量表、不训练。
