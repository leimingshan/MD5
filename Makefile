CC = gcc
CFLAGS = -O2 -m32 -std=c99 -fopenmp -lm

ALL = main
all: ${ALL}

main: mddriver.o md5c.o
	$(CC) md5c.o mddriver.o -o md5 $(CFLAGS)

clean:
	${RM} -r *.o main

