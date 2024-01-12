TARGET := xenon-bltool
ifeq ($(OS),Windows_NT)
	TARGET := $(addsuffix .exe,$(TARGET))
endif

SRC_DIR := source
EXCRYPT_DIR := 3rdparty/excrypt
MSPACK_DIR := 3rdparty/mspack
SOURCES := $(wildcard $(SRC_DIR)/*.c) $(wildcard $(EXCRYPT_DIR)/*.c) $(wildcard $(MSPACK_DIR)/*.c)

INCLUDES := include $(EXCRYPT_DIR) $(MSPACK_DIR)

default: all

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(patsubst %,-I %,$(INCLUDES)) -o $@ $^

.PHONY: all
all: $(TARGET)

.PHONY: clean
clean:
	@-rm -f $(TARGET)
