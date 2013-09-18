CC = gcc
CFLAGS = -O2 -std=c99 -fopenmp -lm

ALL = main
all: ${ALL}

main: mddriver.o md5c.o
	$(CC) md5c.o mddriver.o -o main $(CFLAGS)

clean:
	${RM} -r *.o main

