#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) int classify(int x) {
    switch (x) {
        case 1: return 10;
        case 2: return 20;
        case 3: return 30;
        case 4: return 40;
        case 5: return 50;
        default: return -1;
    }
}

int main(int argc, char** argv) {
    int x = (argc > 1) ? (atoi(argv[1]) % 7) : 3;
    printf("%d\n", classify(x));
    return 0;
}
