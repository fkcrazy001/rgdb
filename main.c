#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int call(int a, int b)
{
    return a + b;
}

int main(int argc, char *argv[])
{
    int i  = 0;
    printf("Hello, World! call(1, 2) = %d\n", call(1, 2));
    return 0;
}