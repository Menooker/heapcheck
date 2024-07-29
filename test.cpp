#include <memory.h>


int main() {
    int* XXX = new int[10];
    XXX[-10]=20;
    delete[] XXX;
    return 0;
}