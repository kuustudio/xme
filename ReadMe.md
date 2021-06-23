# xit

内存加载 DLL 。

注意，无法处理 TLS 情况。请注入的 DLL 需要使用 /Zc:threadSafeInit- 编译。

注意，简单带 TLS 的 DLL ，可能没有问题。但复杂 DLL ，仍然无法处理 TLS 。