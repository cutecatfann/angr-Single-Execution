// gcc -o test_binary_2 test2.c
//#include <stdio.h>

int func1(int x){
    //printf("func1 received integer: %d\n", x);
    return x * 2;
}

int main(){
    int num = 42;
    //printf("main sending integer: %d\n", num);
    
    int result = func1(num);
    
    //printf("main received integer: %d\n", result);
    return 0;
}
