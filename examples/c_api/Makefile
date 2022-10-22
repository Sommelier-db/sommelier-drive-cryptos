MAKEFILE_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
PARENT_DIR := $(shell dirname ${MAKEFILE_DIR})
PROJECT_DIR := $(shell dirname ${PARENT_DIR})
SOURCE = src
OBJECT = object
BUILD = build

OBJECTS = $(OBJECT)/main.o
LIBRARIES = -lsommelier_drive_cryptos

TARGET = $(BUILD)/main
CC = gcc
INCLUDES = ../../target/release
LIBDIR = ../../target/release
CFLAGS = -Wall

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -L$(LIBDIR) -o $(TARGET) $^ $(LIBRARIES)

$(OBJECT)/%.o: $(SOURCE)/%.c
	$(CC) $(CFLAGS) -I$(INCLUDES)  -o $@ -c $<

init:
	mkdir $(BUILD)
	mkdir $(OBJECT)
	mkdir $(LOG)
	mkdir $(DATA)

.PHONY: clean
clean:
	rm -rf $(OBJECTS) $(TARGET)

.PHONY: clean-all
clean-all:
	rm -rf $(OBJECTS) $(TARGET)
