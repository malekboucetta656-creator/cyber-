#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void win() {
    printf("FLAG{pwn_test_success}\n");
    system("/bin/sh");
}

void vulnerable() {
    char buf[64];
    printf("Enter your name: ");
    fgets(buf, 128, stdin);   // overflow volontaire (128 > 64)
    printf("Hello %s", buf);
}

int main() {
    vulnerable();
    return 0;
}
