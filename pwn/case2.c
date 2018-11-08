#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

char g_buf[4];

int main(int argc, char **argv, char**envp){
    int off = atoi(argv[1]);
    srand(time(0) + off);
    g_buf[0] = rand() % 26 + 65;
    g_buf[1] = rand() % 26 + 65;
    g_buf[2] = rand() % 26 + 65;

    unsigned int a,b,c;
    unsigned int d,e;
    a = rand() % 3;
    b = rand() % 3;
    c = rand() % 3;

    d = rand() % 6;
    e = rand() % 6;

    printf("%x,%x,%x,%x,%x,%x,%x,%x", g_buf[0], g_buf[1], g_buf[2], a, b, c, d, e);
    return 0;
}