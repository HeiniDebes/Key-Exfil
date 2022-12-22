#ifndef RECV_H
#define RECV_H

enum {
    AM_BLINKTORADIO = 6
};

typedef nx_struct Msg {
    nx_uint16_t nodeid;
    nx_uint8_t data[16];
} Msg;

#endif