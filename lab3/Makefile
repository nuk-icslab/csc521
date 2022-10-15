# The target name of the executable
TARGET=lab3

# The definition of directories
INCLUDE_DIR=include
SRC_DIR=src
TARGET_DIR=build

# Configuration of compiler and linker
CC=gcc
CFLAGS=-g -O0 -Wall -I$(INCLUDE_DIR) -fsanitize=address
LDFLAGS=-lpcap -fsanitize=address

# Find all of the .c files in SRC_DIR.
# And convert the suffix to .o
DEPS=$(patsubst $(SRC_DIR)/%.c, $(TARGET_DIR)/%.o, $(wildcard $(SRC_DIR)/*.c))

all: $(TARGET_DIR) $(TARGET)

# Make the target directory
$(TARGET_DIR):
	mkdir $(TARGET_DIR)

# Link
$(TARGET): $(DEPS)
	$(CC) -o $@ $^ $(LDFLAGS)

# Compile
$(TARGET_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) -o $@ $^ -c $(CFLAGS)

clean:
	rm -rf $(TARGET_DIR)
	rm -rf $(TARGET)