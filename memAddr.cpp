#include <iostream>
#include <fstream>
#include <cstdlib>
#include <string>
#include <string.h>

using namespace std;


void memory_address(string text){
    string *memAddr = &text;
    cout << memAddr << endl;
}


int main(){
    string text;
    cout << "Enter some text: ";
    cin >> text;
    memory_address(text);
}