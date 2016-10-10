/**
 * @file main.h
 * @author Jiri Zahradnik <xzahra22>
 * @date 3rd October 2016
 * @brief Header file for main.cpp for ISA project.
 */
#include "main.h"

int main(int argc, char *argv[]){
    /* Error messages */
    std::string errMessages[] = {
            "",
            "Bad parameter",
            "Duplicit parameters",
            "Expected integer as an argument",
            "Missing required argument",
            "Unable to estabilish connection",
            "Unknown error"
    };

    /* New object on the heap */
    sniffer *mySniffer = new sniffer();
    int ret = mySniffer->mArgCheck(argc, argv);
    if(E_OK != ret){
        std::cout << errMessages[ret] << std::endl;
    }
    return 0;
}
