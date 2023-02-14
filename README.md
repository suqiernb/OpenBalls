# OpenBalls

## 它是什么

一个跨进程内存读写工具

## 它能做什么

- 读写软件中内存
- 和 [GameGuardian](https://gameguardian.net) 类似

## 如何使用

下载 `OpenBalls.hpp`, 并且将其导入到你的项目中.

```cpp
#include "OpenBalls.hpp"

int main(int args, const char *argv[]) {
    // 获取进程ID
    u32 pid = ballsGetProcessId("com.ztgame.bob");
    printf("ProcessId: %d\n", pid);
    // 得到匿名内存映射表
    std::vector<Smap> maps = ballsGetMaps(pid, REGION_ANONYMOUS);
    // 从中搜索
    std::vector<Addr> result = ballsSearchValue<Dword>(pid, maps, 0x3EA8F5C3);
    printf("Search count: %d\n", result.size());
    // 偏移比较
    ballsOffsetCompare<Dword>(pid, result, 0x04, 0x41200000);
    printf("Offset count: %d\n", result.size());
    ballsOffsetCompare<Float>(pid, result, -0xc4, 0.5f, 5.0f);
    printf("Offset count: %d\n", result.size());
    printf("Result list:\n");
    for (Addr addr: result) {
        printf("%p\n", (Ptr) addr);
    }
    // 循环修改这个地址(冻结)
    while (true) {
        ballsEditValues<Float>(pid, result, -0xc4, 2.0f);
    }

    return 0;
}
```

## 许可证

使用该项目需遵守 Apache License 2.0 许可协议。有关许可证请参阅 `LICENSE`.

## License

This project is licensed under the Apache License, Version 2.0. Please refer to `LICENSE` for the
full text.
