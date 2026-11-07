#include <stdio.h>
#include <stdlib.h>

struct Shape {
    int side;
    Shape(int s) : side(s) {}
    virtual int area() { return 0; }
};

struct Square : Shape {
    Square(int s) : Shape(s) {}
    int area() override { return side * side; }
};

__attribute__((noinline)) int eval_area(Shape* s) {
    return s->area();
}

int main(int argc, char** argv) {
    int side = (argc > 1) ? (atoi(argv[1]) + 4) : 5;
    Square sq(side);
    printf("%d\n", eval_area(&sq));
    return 0;
}
