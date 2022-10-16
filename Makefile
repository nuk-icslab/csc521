SUBDIRS = lab1 lab2 lab3 lab4

.PHONY: all $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@