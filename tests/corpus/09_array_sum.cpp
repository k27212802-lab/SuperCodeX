#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) int sum_array(const int* arr, int n) {
    int total = 0;
    for (int i = 0; i < n; i++) {
        total += arr[i] * (i + 1);
    }
    return total;
}

int main(int argc, char** argv) {
    int seed = (argc > 1) ? atoi(argv[1]) : 1;
    int data[6];
    for (int i = 0; i < 6; i++) {
        data[i] = seed * 3 + i * 5;
    }
    printf("%d\n", sum_array(data, 6));
    return 0;
}
