/**
 * @file error.h
 * @author Jiri Zahradnik <xzahra22>
 * @date 3rd October 2016
 * @brief Error codes for project
 */

#ifndef __ERROR_H__
#define __ERROR_H__

#include <iostream>

enum{
    E_OK = 0,
    E_BADARG,
    E_DUPLICITEARG,
    E_MISSINGREQUIREDARG,
    E_ESTABILISHINGCONNECTION,
    E_UNKNOWN
};

#endif /* __ERROR_H__ */