CC = gcc
CFLAGS = -O2 -std=c99 -fopenmp 

ALL = main convert
all: ${ALL}

main: mddriver.o md5c.o
	$(CC) md5c.o mddriver.o -o main $(CFLAGS)

convert: md5c.o convert62.o
	$(CC) md5c.o convert62.o -o convert $(CFLAGS) -lm

clean:
	${RM} -r *.o main convert 

