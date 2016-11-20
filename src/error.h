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
    E_EXPECTEDINTASARGUMENT,
    E_MISSINGREQUIREDARG,
    E_ESTABILISHINGCONNECTION,
    E_CONNECT_ERROR
};

#endif /* __ERROR_H__ */