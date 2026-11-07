#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

struct Box {
    int64_t tag;
    int64_t width;
    int64_t height;
};

__attribute__((noinline)) int64_t box_metric(const Box* b) {
    return b->width * b->height + b->tag;
}

int main(int argc, char** argv) {
    int s = (argc > 1) ? atoi(argv[1]) : 1;
    Box b = { s * 2, s + 5, s + 9 };
    printf("%lld\n", (long long)box_metric(&b));
    return 0;
}
