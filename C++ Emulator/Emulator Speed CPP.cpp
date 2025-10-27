#include <iostream>
#include <string>
#include <cmath>
#include <ctime>

using namespace std;

//Structure to represent registers
struct {
    //Registers to store operands
    int X86_REG_EAX;
    int X86_REG_EBX;
    int X86_REG_EDX;
    //Instruction register
    int X86_REG_EIP;
} registers;

//Return binary string from hex input
string hexToBinary(char hex) {
    switch(hex) {
        case '0':
            return "0000";
        case '1':
            return "0001";
        case '2':
            return "0010";
        case '3':
            return "0011";
        case '4':
            return "0100";
        case '5':
            return "0101";
        case '6':
            return "0110";
        case '7':
            return "0111";
        case '8':
            return "1000";
        case '9':
            return "1001";
        case 'A':
            return "1010";
        case 'B':
            return "1011";
        case 'C':
            return "1100";
        case 'D':
            return "1101";
        case 'E':
            return "1110";
        case 'F':
            return "1111";
        default:
            return "9999"; //Error value
    }
    return "9999"; //Error value
}

int main() {
    //Initialize variables used to keep track of times
    time_t start_time, end_time;

    //X86 instructions to be executed
    string code = "b8 0A 00 00 00 bb 02 00 00 00 03 c3";

    //Initialize all registers to 0
    registers.X86_REG_EAX = 0;
    registers.X86_REG_EBX = 0;
    registers.X86_REG_EIP = 0;

    //Start time of operation
    time(&start_time); 

    while (registers.X86_REG_EIP < code.length()) {
        //Move value to EAX register
        if (code[registers.X86_REG_EIP] == 'b' && code[registers.X86_REG_EIP + 1] == '8') {
            //Allocate memory to temporarily use to store operand values
            int* value = new int;
            string* binaryString = new string;

            //Retrieve operand values
            *value = 0; //Set initial value to 0
            *binaryString = hexToBinary(code[registers.X86_REG_EIP + 3]) + hexToBinary(code[registers.X86_REG_EIP + 4]); //Convert hex to binary
            if (*binaryString == "9999") { //Detect error value
                cout << "Error";
            }
            for (int i = 0; i < (*binaryString).length(); i++) { //Convert binary to integer
                if ((*binaryString)[i] == '1') {
                    *value += pow(2, 7 - i);
                }
            }

            //Move operand values to EAX register
            registers.X86_REG_EAX = *value;

            //Clean up memory
            delete value;
            delete binaryString;
        }
        //Move value to EBX register
        else if (code[registers.X86_REG_EIP] == 'b' && code[registers.X86_REG_EIP + 1] == 'b') {
            //Allocate memory to temporarily use to store operand values
            int* value = new int;
            string* binaryString = new string;

            //Retrieve operand values
            *value = 0; //Set initial value to 0
            *binaryString = hexToBinary(code[registers.X86_REG_EIP + 3]) + hexToBinary(code[registers.X86_REG_EIP + 4]); //Convert hex to binary
            if (*binaryString == "9999") { //Detect error value
                cout << "Error";
            }
            for (int i = 0; i < (*binaryString).length(); i++) { //Convert binary to integer
                if ((*binaryString)[i] == '1') {
                    *value += pow(2, 7 - i);
                }
            }

            //Move operand values to EAX register
            registers.X86_REG_EBX = *value;

            //Clean up memory
            delete value;
            delete binaryString;
        }
        //Add value from EAX and EBX registers
        else if (code[registers.X86_REG_EIP] == '0' && code[registers.X86_REG_EIP + 1] == '3' && code[registers.X86_REG_EIP + 3] == 'c' && code[registers.X86_REG_EIP + 4] == '3') {
            registers.X86_REG_EAX = registers.X86_REG_EAX + registers.X86_REG_EBX;
        }

        registers.X86_REG_EIP += 15;
    }
    
    //End time of operation
    time(&end_time);

    //Calculate the difference in seconds
    float time = difftime(end_time, start_time);

    cout << start_time  << " seconds" << endl;
    cout << end_time  << " seconds" << endl;

    cout << "Time difference: " << time << " seconds" << endl;

    return 0;
}