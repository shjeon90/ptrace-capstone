# capstone library name (without prefix 'lib' and suffix '.so')
LIBNAME = capstone

bb-counter: bb-counter.o
	${CC} $< -O3 -Wall -l$(LIBNAME) -o $@ 
	
%.o: %.c
	${CC} -c $< -o $@
