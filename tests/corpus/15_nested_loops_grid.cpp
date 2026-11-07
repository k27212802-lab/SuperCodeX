#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) int grid_accumulate(int rows, int cols) {
    int total = 0;
    for (int r = 1; r <= rows; r++) {
        for (int c = 1; c <= cols; c++) {
            if ((r + c) % 2 == 0) {
                total += r * c;
            } else {
                total += r + c;
            }
        }
    }
    return total;
}

int main(int argc, char** argv) {
    int n = (argc > 1) ? ((atoi(argv[1]) % 6) + 2) : 4;
    printf("%d\n", grid_accumulate(n, n + 1));
    return 0;
}
