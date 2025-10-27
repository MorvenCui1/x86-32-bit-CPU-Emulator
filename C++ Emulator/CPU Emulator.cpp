#include <iostream>
#include <string>
#include <cmath>

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
    //X86 instructions to be executed
    string code = "b8 0A 00 00 00 bb 02 00 00 00 03 c3";

    //Initialize all registers to 0
    registers.X86_REG_EAX = 0;
    registers.X86_REG_EBX = 0;
    registers.X86_REG_EDX = 0;
    registers.X86_REG_EIP = 0;

    //Set reset pin to initially false
    bool reset = false;

    while (registers.X86_REG_EIP < code.length()) {
        if (reset == true) { //If reset is true set all registers back to initial value
            registers.X86_REG_EAX = 0;
            registers.X86_REG_EBX = 0;
            registers.X86_REG_EDX = 0;
            reset = false;
        }
        
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

            //Print new register value
            cout << "EAX Register Value: " << registers.X86_REG_EAX << "\n";
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

            //Print new register value
            cout << "EBX Register Value: " << registers.X86_REG_EBX << "\n";
        }
        //Move value from EAX register to EBX register
        else if (code[registers.X86_REG_EIP] == '8' && code[registers.X86_REG_EIP + 1] == '9' && code[registers.X86_REG_EIP + 3] == 'D' && code[registers.X86_REG_EIP + 4] == '8') {
            registers.X86_REG_EBX = registers.X86_REG_EAX;

            cout << "Register EBX Value: " << registers.X86_REG_EBX << "\n";
        }
        //Move value from EBX register to EAX register
        else if (code[registers.X86_REG_EIP] == '8' && code[registers.X86_REG_EIP + 1] == 'B' && code[registers.X86_REG_EIP + 3] == 'C' && code[registers.X86_REG_EIP + 4] == '3') {
            registers.X86_REG_EAX = registers.X86_REG_EBX;

            cout << "Register EAX Value: " << registers.X86_REG_EAX << "\n";
        }
        //Add value from EAX and EBX registers
        else if (code[registers.X86_REG_EIP] == '0' && code[registers.X86_REG_EIP + 1] == '3' && code[registers.X86_REG_EIP + 3] == 'c' && code[registers.X86_REG_EIP + 4] == '3') {
            registers.X86_REG_EAX = registers.X86_REG_EAX + registers.X86_REG_EBX;

            cout << "Register EAX Value: " << registers.X86_REG_EAX << "\n";
        }
        //Subtract value from EAX and EBX registers
        else if (code[registers.X86_REG_EIP] == '2' && code[registers.X86_REG_EIP + 1] == 'B' && code[registers.X86_REG_EIP + 3] == 'C' && code[registers.X86_REG_EIP + 4] == '3') {
            registers.X86_REG_EAX = registers.X86_REG_EAX - registers.X86_REG_EBX;
            cout << "Register EAX Value: " << registers.X86_REG_EAX << "\n";
        }
        //Signed multiply value from EAX and EBX registers
        else if (code[registers.X86_REG_EIP] == '0' && code[registers.X86_REG_EIP + 1] == 'F' && code[registers.X86_REG_EIP + 3] == 'A' && code[registers.X86_REG_EIP + 4] == 'F' && code[registers.X86_REG_EIP + 6] == 'C' && code[registers.X86_REG_EIP + 7] == '3') {
            registers.X86_REG_EAX = registers.X86_REG_EAX * registers.X86_REG_EBX;

            cout << "Register EAX Value: " << registers.X86_REG_EAX << "\n";
        }
        //Unsigned multiply value from EAX and EBX registers
        else if (code[registers.X86_REG_EIP] == 'F' && code[registers.X86_REG_EIP + 1] == '7' && code[registers.X86_REG_EIP + 3] == 'E' && code[registers.X86_REG_EIP + 4] == '3') {
            registers.X86_REG_EAX = abs(registers.X86_REG_EAX * registers.X86_REG_EBX);

            cout << "Register EAX Value: " << registers.X86_REG_EAX << "\n";
        }
        //Signed division value from EAX and EBX registers
        else if (code[registers.X86_REG_EIP] == 'F' && code[registers.X86_REG_EIP + 1] == '7' && code[registers.X86_REG_EIP + 3] == 'F' && code[registers.X86_REG_EIP + 4] == 'B') {
            registers.X86_REG_EDX = registers.X86_REG_EAX % registers.X86_REG_EBX;
            registers.X86_REG_EAX = registers.X86_REG_EAX / registers.X86_REG_EBX;
            
            cout << "Register EAX Value: " << registers.X86_REG_EAX << "\n";
            cout << "Register EDX Value: " << registers.X86_REG_EDX << "\n";
        }
        //Unsigned division value from EAX and EBX registers
        else if (code[registers.X86_REG_EIP] == 'F' && code[registers.X86_REG_EIP + 1] == '7' && code[registers.X86_REG_EIP + 3] == 'F' && code[registers.X86_REG_EIP + 4] == '3') {
            registers.X86_REG_EDX = abs(registers.X86_REG_EAX % registers.X86_REG_EBX);
            registers.X86_REG_EAX = abs(registers.X86_REG_EAX / registers.X86_REG_EBX);

            cout << "Register EAX Value: " << registers.X86_REG_EAX << "\n";
            cout << "Register EDX Value: " << registers.X86_REG_EDX << "\n";
        }
        //Unimplemented instruction
        else {
            cout << "Instruction not supported" << "\n";
        }

        registers.X86_REG_EIP += 15;
    }

    return 0;
}