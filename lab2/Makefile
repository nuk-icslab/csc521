# The target name of the executable
NAME= lab2

# Configuration of compiler and linker
SRCDIR := src
OBJDIR := build
LIBDIR := ../lib/src
CONFIG := config

CC := gcc
FLAGS := $(shell cat $(CONFIG) | awk '/^[^\#]+$$/ {print "-D"$$0}' ORS=' ')
CFLAGS := -g -O2 -Wall -fsanitize=address $(FLAGS)
INCLUDES := -Isrc -I../lib/include
LDFLAGS := -lpcap -fsanitize=address

# Find all of the .c files in SRCDIR.
SRCS := $(wildcard $(SRCDIR)/*.c)
OBJS := $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SRCS))
LIB_SRCS := util.c netdevice.c arp.c
LIB_OBJS := $(addprefix $(OBJDIR)/, $(LIB_SRCS:.c=.o))
LIB_SRCS := $(addprefix $(LIBDIR)/, $(LIB_SRCS))

#$(info SRCS=$(SRCS))
#$(info LIB_SRCS=$(LIB_SRCS))
#$(info FLAGS=$(FLAGS))

.PHONY: all clean
all: $(NAME)
	@echo "Successfully built $(NAME)"

$(NAME): $(OBJS) $(LIB_OBJS)
	$(CC) $(LDFLAGS) $^ -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJS): $(OBJDIR)/%.o: $(SRCDIR)/%.c $(CONFIG) | $(OBJDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(LIB_OBJS): $(OBJDIR)/%.o: $(LIBDIR)/%.c $(CONFIG) | $(OBJDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	-rm $(NAME)
	-rm -rf $(OBJDIR)