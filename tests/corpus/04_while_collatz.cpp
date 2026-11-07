#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) int collatz_steps(int n) {
    int steps = 0;
    while (n > 1) {
        if ((n & 1) == 0) {
            n = n / 2;
        } else {
            n = 3 * n + 1;
        }
        steps++;
    }
    return steps;
}

int main(int argc, char** argv) {
    int n = (argc > 1) ? (atoi(argv[1]) + 3) : 7;
    printf("%d\n", collatz_steps(n));
    return 0;
}
