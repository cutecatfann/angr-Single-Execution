

void func1(int *val){
    // when analyzing func1, we don't want the address to be symbolic
    // we want the value at that address to be sybmolic (I think)
    *val = 5;
}

void main(){
    int val2 = 4;
    // because we are passing in a pointer that func1 might change
    // val2 is now symbolic
    func1(&val2);
}
