// gcc -o test_binary test.c
#include <stdio.h>

void func1(){
    printf("Hello from func1!\n");
}

int main(){
    printf("Hello from main!\n");
    func1();
    return 0;
}
