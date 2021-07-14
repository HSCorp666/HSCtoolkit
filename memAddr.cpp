#include <iostream>
#include <string>
#include <string.h>

using namespace std;


void memory_address(string text){
    string *memAddr = &text;
    cout << memAddr << endl;
}


int main(){
    string text;
    cout << "option(enter-some-text)>> ";
    cin >> text;
    memory_address(text);
}
