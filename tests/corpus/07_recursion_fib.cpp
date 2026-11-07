#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) int fib(int n) {
    if (n <= 1) return n;
    return fib(n - 1) + fib(n - 2);
}

int main(int argc, char** argv) {
    int n = (argc > 1) ? ((atoi(argv[1]) % 12) + 1) : 8;
    printf("%d\n", fib(n));
    return 0;
}
