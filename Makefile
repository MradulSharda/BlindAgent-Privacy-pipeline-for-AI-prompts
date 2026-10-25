CC ?= clang
CFLAGS ?= -O3 -Wall -Wextra -pedantic -std=c99 -fPIC
TARGET_LIB = libblindcrypto.dylib
TARGET_TEST = test_engine

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    TARGET_LIB = libblindcrypto.so
    SHLIB_FLAGS = -shared -Wl,-soname,$(TARGET_LIB)
endif
ifeq ($(UNAME_S),Darwin)
    TARGET_LIB = libblindcrypto.dylib
    SHLIB_FLAGS = -dynamiclib -install_name @rpath/$(TARGET_LIB)
endif

all: $(TARGET_LIB) $(TARGET_TEST)

$(TARGET_LIB): core/crypto_engine.c core/crypto_engine.h
	$(CC) $(CFLAGS) $(SHLIB_FLAGS) core/crypto_engine.c -o $(TARGET_LIB)

$(TARGET_TEST): core/test_engine.c core/crypto_engine.c core/crypto_engine.h
	$(CC) $(CFLAGS) core/test_engine.c core/crypto_engine.c -o $(TARGET_TEST)

test: $(TARGET_TEST)
	./$(TARGET_TEST)

clean:
	rm -f $(TARGET_LIB) $(TARGET_TEST) *.o

.PHONY: all test clean
