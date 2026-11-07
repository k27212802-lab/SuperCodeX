#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) int gcd(int a, int b) {
    while (b != 0) {
        int t = a % b;
        a = b;
        b = t;
    }
    return a;
}

int main(int argc, char** argv) {
    int s = (argc > 1) ? atoi(argv[1]) : 1;
    int a = 36 * s + 12;
    int b = 18 * s + 30;
    printf("%d\n", gcd(a, b));
    return 0;
}
