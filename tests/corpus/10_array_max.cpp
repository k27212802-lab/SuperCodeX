#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) int max_element_val(const int* arr, int n) {
    int best = arr[0];
    for (int i = 1; i < n; i++) {
        if (arr[i] > best) {
            best = arr[i];
        }
    }
    return best;
}

int main(int argc, char** argv) {
    int seed = (argc > 1) ? atoi(argv[1]) : 1;
    int data[6];
    for (int i = 0; i < 6; i++) {
        data[i] = ((seed * 19 + i * 37) % 97) - 20;
    }
    printf("%d\n", max_element_val(data, 6));
    return 0;
}
