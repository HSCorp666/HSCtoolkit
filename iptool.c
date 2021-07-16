#include <stdio.h>
#include <stdlib.h>
#include <regex.h>
#include <string.h>


void get_gateway(){
    system("ip r >gateway.txt");
}



int main(){
    printf("Getting gateway address..");
    get_gateway();
}