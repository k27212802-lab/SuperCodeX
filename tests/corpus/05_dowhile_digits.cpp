#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) int sum_digits(int x) {
    if (x < 0) x = -x;
    int sum = 0;
    do {
        sum += x % 10;
        x /= 10;
    } while (x > 0);
    return sum;
}

int main(int argc, char** argv) {
    int val = (argc > 1) ? (atoi(argv[1]) * 137 + 9) : 12345;
    printf("%d\n", sum_digits(val));
    return 0;
}
