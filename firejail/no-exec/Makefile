all: link.o hello hello-static exec exec-static

exec: exec.c
	gcc exec.c -o exec

exec-static: exec.c
	gcc exec.c -o exec-static -static
