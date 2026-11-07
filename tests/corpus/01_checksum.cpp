#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" __attribute__((noinline)) uint32_t checksum(const uint8_t* p, int n) {
    uint32_t h = 0x811C9DC5;
    for (int i = 0; i < n; i++) {
        h ^= p[i];
        h *= 16777619u;
        if (h & 1) h += 7;
    }
    return h;
}

int main(int argc, char** argv) {
    int seed = (argc > 1) ? atoi(argv[1]) : 1;
    uint8_t buf[8];
    for (int i = 0; i < 8; i++) {
        buf[i] = (uint8_t)((seed * 17 + i * 31) & 0xFF);
    }
    printf("%u\n", checksum(buf, 8));
    return 0;
}
