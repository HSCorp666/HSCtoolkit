#include <iostream>
#include <cstdlib>
#include <ctime>

using namespace std;

const char alphaNum[] = "abcdefghijklmnopqrstuvwxyz12345678-=!@#$%^&*_+ABCDEFGHIJKLMNOPQRSTUVWXYZ";
int stringLength = sizeof(alphaNum) - 1;

int main(){
    int passwordLength;

    cout << "option(password-length)>> ";
    cin >> passwordLength;

    cout << "Generated Password: ";

    for(int i=0; i < passwordLength; ++i){
        cout << alphaNum[rand() % stringLength];
    }

    cout << endl;
}