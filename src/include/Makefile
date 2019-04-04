## Makefile to compile stand-alone client

## Comment this or set 0 to disable HTTPS support
HTTPS:=1

TARGET = client
LIBS  = -lpthread
CFLAGS = -Wall -Wextra -Wfatal-errors -Wunused -ggdb -O0 -DDEBUG -DSTAND_ALONE

ifeq ($(HTTPS),1)
CFLAGS += -DENABLE_HTTPS
LIBS += -lssl -lcrypto
endif

SRC=$(wildcard *.c)

$(TARGET): $(SRC)
	gcc -o $@ $^ $(CFLAGS) $(LIBS)
clean:
	rm -rf *.o $(TARGET)
