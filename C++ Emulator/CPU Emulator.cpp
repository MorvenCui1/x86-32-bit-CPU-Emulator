#include <iostream>
#include <string>
#include <cmath>

using namespace std;

//Structure to represent registers
struct {
    //Registers to store operands
    int X86_REG_EAX;
    int X86_REG_EBX;
    int X86_REG_ECX;
    int X86_REG_EDX;
    //Instruction register
    int X86_REG_EIP;
    //Stack register
    int X86_REG_ESP;
} registers;

//Stack
int stack[32];

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

//Get operand in decimal from little endian hex values
int getOperand(string hexCode) {
    int* value = new int; //Allocate temporary memory for value
    *value = 0; //Set initial value to 0

    string* binaryString = new string; //Allocate temporary memory for binary string
    *binaryString = ""; //Initialize as empty string to add binary in little endian order from MSB to LSB
    for (int i = 0; i <= 3; i++) {
        *binaryString = *binaryString + hexToBinary(hexCode[6 - 2*i]) + hexToBinary(hexCode[7 - 2*i]);
    }

    for (int i = 1; i < (*binaryString).length(); i++) { //Convert two's complement binary to signed integer
        if ((*binaryString)[i] == '1') {
            *value += pow(2, (*binaryString).length() - 1 - i);
        }
    }
    if ((*binaryString)[0] == '1') {
        *value -= pow(2, (*binaryString).length() - 1);
    }

    return *value;
}

int main() {
    //X86 instructions to be executed
    string code;
    //code = "B801000000BBFFFFFFFF03C3"; //Add 1 and -1
    code = "E818000000B801000000CD80B8FFFFFFFFC3"; //Branch to subroutine, load -1 into EAX, return, and exit system in linux

    //Initialize all registers to 0
    registers.X86_REG_EAX = 0;
    registers.X86_REG_EBX = 0;
    registers.X86_REG_ECX = 0;
    registers.X86_REG_EDX = 0;
    registers.X86_REG_EIP = 0;
    //Initialize stack pointer to top of stack
    registers.X86_REG_ESP = 32;

    //Set reset pin to initially false
    bool reset = false;

    //Loop through instructions
    while (registers.X86_REG_EIP < code.length()) {
        if (reset == true) { //If reset is true set all registers back to initial value
            registers.X86_REG_EAX = 0;
            registers.X86_REG_EBX = 0;
            registers.X86_REG_ECX = 0;
            registers.X86_REG_EDX = 0;
            registers.X86_REG_EIP = 0;
            registers.X86_REG_ESP = 32;
            //Reset stack
            for (int i = 0; i < 32; ++i) {
                stack[i] = 0;
            }
            //Reset is false
            reset = false;
        }
        
        //Move value to EAX register
        if (code[registers.X86_REG_EIP] == 'B' && code[registers.X86_REG_EIP + 1] == '8') {
            //Allocate memory to temporarily use to store operand values
            int* value = new int;
            string* hexString = new string;
            //Retrieve operand values
            *hexString = "";
            for (int i = 1; i <= 4; i++) {
                *hexString = *hexString + code[registers.X86_REG_EIP + 2*i] + code[registers.X86_REG_EIP + 2*i + 1];
            }
            *value = getOperand(*hexString);

            //Move operand values to EAX register
            registers.X86_REG_EAX = *value;

            //Clean up memory
            delete value;
            delete hexString;

            //Print new register value
            cout << "EAX Register Value: " << registers.X86_REG_EAX << "\n";

            registers.X86_REG_EIP += 10; //Sets instruction pointer to next instruction
        }
        //Move value to EBX register
        else if (code[registers.X86_REG_EIP] == 'B' && code[registers.X86_REG_EIP + 1] == 'B') {
            //Allocate memory to temporarily use to store operand values
            int* value = new int;
            string* hexString = new string;
            //Retrieve operand values
            *hexString = "";
            for (int i = 1; i <= 4; i++) {
                *hexString = *hexString + code[registers.X86_REG_EIP + 2*i] + code[registers.X86_REG_EIP + 2*i + 1];
            }
            *value = getOperand(*hexString);

            //Move operand values to EBX register
            registers.X86_REG_EBX = *value;

            //Clean up memory
            delete value;
            delete hexString;

            //Print new register value
            cout << "EBX Register Value: " << registers.X86_REG_EBX << "\n";

            registers.X86_REG_EIP += 10; //Sets instruction pointer to next instruction
        }
        //Move value from EAX register to EBX register
        else if (code[registers.X86_REG_EIP] == '8' && code[registers.X86_REG_EIP + 1] == '9' && code[registers.X86_REG_EIP + 2] == 'D' && code[registers.X86_REG_EIP + 3] == '8') {
            registers.X86_REG_EBX = registers.X86_REG_EAX;

            cout << "Register EBX Value: " << registers.X86_REG_EBX << "\n";

            registers.X86_REG_EIP += 4; //Sets instruction pointer to next instruction
        }
        //Move value from EBX register to EAX register
        else if (code[registers.X86_REG_EIP] == '8' && code[registers.X86_REG_EIP + 1] == 'B' && code[registers.X86_REG_EIP + 2] == 'C' && code[registers.X86_REG_EIP + 3] == '3') {
            registers.X86_REG_EAX = registers.X86_REG_EBX;

            cout << "Register EAX Value: " << registers.X86_REG_EAX << "\n";

            registers.X86_REG_EIP += 4; //Sets instruction pointer to next instruction
        }
        //Add value from EAX and EBX registers
        else if (code[registers.X86_REG_EIP] == '0' && code[registers.X86_REG_EIP + 1] == '3' && code[registers.X86_REG_EIP + 2] == 'C' && code[registers.X86_REG_EIP + 3] == '3') {
            registers.X86_REG_EAX = registers.X86_REG_EAX + registers.X86_REG_EBX;

            cout << "Register EAX Value: " << registers.X86_REG_EAX << "\n";

            registers.X86_REG_EIP += 4; //Sets instruction pointer to next instruction
        }
        //Subtract value from EAX and EBX registers
        else if (code[registers.X86_REG_EIP] == '2' && code[registers.X86_REG_EIP + 1] == 'B' && code[registers.X86_REG_EIP + 2] == 'C' && code[registers.X86_REG_EIP + 3] == '3') {
            registers.X86_REG_EAX = registers.X86_REG_EAX - registers.X86_REG_EBX;
            cout << "Register EAX Value: " << registers.X86_REG_EAX << "\n";

            registers.X86_REG_EIP += 4; //Sets instruction pointer to next instruction
        }
        //Signed multiply value from EAX and EBX registers
        else if (code[registers.X86_REG_EIP] == '0' && code[registers.X86_REG_EIP + 1] == 'F' && code[registers.X86_REG_EIP + 2] == 'A' && code[registers.X86_REG_EIP + 3] == 'F' && code[registers.X86_REG_EIP + 4] == 'C' && code[registers.X86_REG_EIP + 5] == '3') {
            registers.X86_REG_EAX = registers.X86_REG_EAX * registers.X86_REG_EBX;

            cout << "Register EAX Value: " << registers.X86_REG_EAX << "\n";

            registers.X86_REG_EIP += 6; //Sets instruction pointer to next instruction
        }
        //Unsigned multiply value from EAX and EBX registers
        else if (code[registers.X86_REG_EIP] == 'F' && code[registers.X86_REG_EIP + 1] == '7' && code[registers.X86_REG_EIP + 2] == 'E' && code[registers.X86_REG_EIP + 3] == '3') {
            registers.X86_REG_EAX = abs(registers.X86_REG_EAX * registers.X86_REG_EBX);

            cout << "Register EAX Value: " << registers.X86_REG_EAX << "\n";

            registers.X86_REG_EIP += 4; //Sets instruction pointer to next instruction
        }
        //Signed division value from EAX and EBX registers
        else if (code[registers.X86_REG_EIP] == 'F' && code[registers.X86_REG_EIP + 1] == '7' && code[registers.X86_REG_EIP + 2] == 'F' && code[registers.X86_REG_EIP + 3] == 'B') {
            registers.X86_REG_EDX = registers.X86_REG_EAX % registers.X86_REG_EBX;
            registers.X86_REG_EAX = registers.X86_REG_EAX / registers.X86_REG_EBX;
            
            cout << "Register EAX Value: " << registers.X86_REG_EAX << "\n";
            cout << "Register EDX Value: " << registers.X86_REG_EDX << "\n";

            registers.X86_REG_EIP += 4; //Sets instruction pointer to next instruction
        }
        //Unsigned division value from EAX and EBX registers
        else if (code[registers.X86_REG_EIP] == 'F' && code[registers.X86_REG_EIP + 1] == '7' && code[registers.X86_REG_EIP + 2] == 'F' && code[registers.X86_REG_EIP + 3] == '3') {
            registers.X86_REG_EDX = abs(registers.X86_REG_EAX % registers.X86_REG_EBX);
            registers.X86_REG_EAX = abs(registers.X86_REG_EAX / registers.X86_REG_EBX);

            cout << "Register EAX Value: " << registers.X86_REG_EAX << "\n";
            cout << "Register EDX Value: " << registers.X86_REG_EDX << "\n";

            registers.X86_REG_EIP += 4; //Sets instruction pointer to next instruction
        }
        //Branch to subroutine address
        else if (code[registers.X86_REG_EIP] == 'E' && code[registers.X86_REG_EIP + 1] == '8') {
            registers.X86_REG_ESP--; //Decrement stack pointer
            stack[registers.X86_REG_ESP] = registers.X86_REG_EIP + 10; //Load next instruction address into stack 

            //Allocate memory to temporarily use to store operand values
            int* value = new int;
            string* hexString = new string;
            //Retrieve operand values
            *hexString = "";
            for (int i = 1; i <= 4; i++) {
                *hexString = *hexString + code[registers.X86_REG_EIP + 2*i] + code[registers.X86_REG_EIP + 2*i + 1];
            }
            *value = getOperand(*hexString);

            registers.X86_REG_EIP = registers.X86_REG_EIP + *value; //Change instruction pointer by offset

            delete value; 
            delete hexString;

            cout << "Jumped to address: " << registers.X86_REG_EIP << "\n";
        }
        //Return to original address before branching
        else if (code[registers.X86_REG_EIP] == 'C' && code[registers.X86_REG_EIP + 1] == '3') {
            registers.X86_REG_EIP = stack[registers.X86_REG_ESP]; //Set instruction pointer to address in stack address
            stack[registers.X86_REG_ESP] = 0; //Clear stack address
            registers.X86_REG_ESP++; //Increment stack pointer

            cout << "Returned to address: " << registers.X86_REG_EIP << "\n";
        }
        //exit system call on Linux
        else if (code[registers.X86_REG_EIP] == 'C' && code[registers.X86_REG_EIP + 1] == 'D' 
            && code[registers.X86_REG_EIP + 2] == '8' && code[registers.X86_REG_EIP + 3] == '0') {
                if (registers.X86_REG_EAX == 1 && registers.X86_REG_EBX == 0) {
                    cout << "Exit program";
                    break;
                }
        }
        //Unimplemented instruction
        else {
            cout << "Instruction not supported" << "\n";
            break;
        }
    }

    return 0;
}