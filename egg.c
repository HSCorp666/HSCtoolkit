#include <stdio.h>
#include <stdlib.h>

int main(){
    const char egger[] = "7e17175d162cbb7fc27f8bb9ad70538a459171b13b6a46e8aeeb7c6ccd806883";
    const int EGGER_SIZE = sizeof(egger) - 1;

    for(int i=0; i < EGGER_SIZE; ++i){
        printf(":) Be happy: %c\n", egger[i]);
    }
}