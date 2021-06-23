CFLAGS += /Zc:threadSafeInit-

xme.o                   : xme.h
main.o                  : xme.h

OBJ =  xme.o main.o