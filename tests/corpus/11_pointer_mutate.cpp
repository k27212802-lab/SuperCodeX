#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) void transform_inplace(int* p, int n, int delta) {
    for (int i = 0; i < n; i++) {
        p[i] = p[i] * 2 + delta;
    }
}

int main(int argc, char** argv) {
    int seed = (argc > 1) ? atoi(argv[1]) : 1;
    int arr[4] = { seed, seed + 2, seed + 4, seed + 6 };
    transform_inplace(arr, 4, 7);
    printf("%d\n", arr[0] + arr[1] + arr[2] + arr[3]);
    return 0;
}
