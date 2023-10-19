

int func1(int val){

    return val + 1;
}

void main(){
    // if we call a function that returns a value, 
    // we need to make mainval symbolic
    int mainval = func1(5);
}
