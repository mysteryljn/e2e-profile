# e2e-profile

纯软件 AUTOSAR E2E 风格保护实验室，提供 CRC-8 SAE J1850 多项式（Profile 1 的 0x00 初始值和最终异或值）、滚动计数器、Data ID 和重复/跳变检测。它用于验证应用层数据保护逻辑，不连接 CAN 或 SOME/IP 硬件。

## 痛点

E2E 保护的边界条件通常藏在供应商实现和集成测试里，计数器重复、跳变和 CRC 错误需要大量手工用例。这个项目给出可读、确定性的参考实现，方便做协议回归和 FMEA 讨论。

## 使用

    python e2e.py protect 0102 --counter 3 --data-id 4660

计数器取值为 `0..14`，从 `14` 回卷到 `0`，`15` 为保留值。CRC 输入依次为 Data ID 低字节、高字节、计数器和载荷。固定向量参考 [AUTOSAR R22-11 E2E Protocol](https://www.autosar.org/fileadmin/standards/R22-11/FO/AUTOSAR_PRS_E2EProtocol.pdf) 第 101 页表 6.20、6.21。

本工具使用简化的 `[counter, CRC, payload...]` 帧布局，不是完整的 AUTOSAR Profile 1 实现。第五轮审查修正了 CRC 输入顺序，旧版生成的 CRC 帧需重新生成；例如载荷 `616263`、计数器 `3`、Data ID `4660` 的结果现在是 `03d2616263`。

## 许可证

MIT
