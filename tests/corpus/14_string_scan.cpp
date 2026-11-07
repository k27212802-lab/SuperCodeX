#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) int string_weight(const char* s, int factor) {
    int acc = 0;
    for (int i = 0; s[i] != 0; i++) {
        if (s[i] >= 'a' && s[i] <= 'z') {
            acc += (s[i] - 'a' + 1) * factor;
        } else {
            acc += 3;
        }
    }
    return acc;
}

int main(int argc, char** argv) {
    int f = (argc > 1) ? atoi(argv[1]) : 2;
    puts("elf64-decompiler-check");
    printf("%d\n", string_weight("supercodex_elf64", f));
    return 0;
}
