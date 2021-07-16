#include <iostream>
#include <string>
#include <string.h>
#include <cmath>
#include <math.h>


/*
This program is a calculator I made because why not.
It is meant for the python program: HSCtoolkit.py.
It is math I love math, cause I am a nerd lol.
*/


using namespace std;  // Yes, I am very lazy.


class Calculator{
    public:
        int add(int number, int number1){
            num_s(number);
            num1_s(number1);

            return num + num1;
        }

        int subtract(int number, int number1){
            num_s(number);
            num1_s(number1);

            return num - num1;
        }


        int multiply(int number, int number1){
            num_s(number);
            num1_s(number1);

            return num * num1;
        }

        int sqrt(int number){
            num_s(number);

            return pow(num, 0.5);
        }

        void num_s(int n){
            num = n;
        }

        void num1_s(int n1){
            num1 = n1;
        }

    private:
        int num;
        int num1;
};


bool ran = false;  // So we do not go spamming the help menu.


int main(){
    string cmd;
    Calculator calc;  // Calculator object.
    int num;
    int num1;

    if(not ran){
    cout << endl;
    cout << "Calculator commands:\n1. add\n2. subtract\n3. multiply\n4. sqrt\n5. exit" << endl;
    cout << endl;
    }

    ran = true;

    cout << "calc(cmd)>> ";
    cin >> cmd;
    if(cmd == "add"){
        cout << "calc(num)>> ";
        cin >> num;
        cout << "calc(num1)>> ";
        cin >> num1;
        cout << calc.add(num, num1) << endl;
        main();
    }
    else if(cmd == "sqrt"){
        cout << "calc(num)>> ";
        cin >> num;
        cout << calc.sqrt(num) << endl;
        main();
    }
    else if(cmd == "subtract"){
        cout << "calc(num)>> ";
        cin >> num;
        cout << "calc(num1)>> ";
        cin >> num1;
        cout << calc.subtract(num, num1) << endl;  // Subtracts num and num1
        main();
    }
    else if(cmd == "multiply"){
        cout << "calc(num)>> ";
        cin >> num;
        cout << "calc(num1)>> ";
        cin >> num1;
        cout << calc.multiply(num, num1);
        main();
    }
    else if(cmd == "exit"){
        return 0;
    }
    else{
        cout << "Invalid command." << endl;
        main();
    }
}