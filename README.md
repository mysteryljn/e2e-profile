# e2e-profile

纯软件 AUTOSAR E2E 风格保护实验室，提供 CRC-8 SAE J1850、滚动计数器、Data ID 和重复/跳变检测。它用于验证应用层数据保护逻辑，不连接 CAN 或 SOME/IP 硬件。

## 痛点

E2E 保护的边界条件通常藏在供应商实现和集成测试里，计数器重复、跳变和 CRC 错误需要大量手工用例。这个项目给出可读、确定性的参考实现，方便做协议回归和 FMEA 讨论。

## 使用

    python e2e.py protect 0102 --counter 3 --data-id 4660

## 许可证

MIT
