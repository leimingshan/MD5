CC = gcc -fopenmp
CFLAGS = -O2 

main: mddriver.o md5c.o
	$(CC) md5c.o mddriver.o -o main $(CFLAGS)

clean:
	${RM} -r *.o main 

