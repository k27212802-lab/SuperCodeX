#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) int grade_bucket(int score) {
    if (score >= 90) {
        return 5;
    } else if (score >= 75) {
        return 4;
    } else if (score >= 60) {
        return 3;
    } else if (score >= 40) {
        return 2;
    } else {
        return 1;
    }
}

int main(int argc, char** argv) {
    int s = (argc > 1) ? ((atoi(argv[1]) * 13) % 105) : 82;
    printf("%d\n", grade_bucket(s));
    return 0;
}
