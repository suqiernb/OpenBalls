#include "OpenBalls.hpp"


int main(int args, const char *argv[]) {
    u32 pid = ballsGetProcessId("com.ztgame.bob");
    printf("ProcessId: %d\n", pid);
    std::vector<Smap> maps = ballsGetMaps(pid, REGION_ANONYMOUS);
    std::vector<Addr> result = ballsSearchValue<Dword>(pid, maps, 0x3EA8F5C3);
    printf("Search count: %d\n", result.size());
    ballsOffsetCompare<Dword>(pid, result, 0x04, 0x41200000);
    printf("Offset count: %d\n", result.size());
    ballsOffsetCompare<Float>(pid, result, -0xc4, 0.5f, 5.0f);
    printf("Offset count: %d\n", result.size());
    printf("Result list:\n");
    for (Addr addr: result) {
        printf("%p\n", (Ptr) addr);
    }

    while (true) {
        ballsEditValues<Float>(pid, result, -0xc4, 2.0f);
    }

    return 0;
}