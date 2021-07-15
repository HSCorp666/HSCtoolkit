#include <iostream>
#include <string>
#include <string.h>
#include <cstdlib>
#include <ctime>
#include <fstream>

using namespace std;


fstream f;
string password; // Password from input.

void brute(string filename, string pass){  // Brute force function.
    f.open(filename);
    string passGuess;

    while(getline(f, passGuess)){
        cout << "Trying password: " << passGuess << endl;

        if(passGuess == password){
            cout << "\n" << "Password found: " << passGuess << endl;
            break;
        }
    }
}



int main(){
    string fileName;

    cout << "option(wordlist)>> ";
    cin >> fileName;

    cout << "option(random-password)>> ";
    cin >> password;

    brute(fileName, password);
}