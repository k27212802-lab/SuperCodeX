#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) int compute(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        if (i % 2 == 0) {
            s += i / 3;
        } else {
            s ^= i;
        }
    }
    return s;
}

int main(int argc, char** argv) {
    int n = (argc > 1) ? atoi(argv[1]) + 5 : 10;
    printf("%d\n", compute(n));
    return 0;
}
