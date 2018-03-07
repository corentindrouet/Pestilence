EXEC		=	pestilence
SRC			=	main.s \
				checkdbg.s \
				checkproc.s \
				readdir.s \
				infect.s \
				ft_strlen.s \
				ft_strequ.s \
				ft_strstr.s \
				file_size.s
OBJ			=	$(SRC:.s=.o)
NASM		=	nasm
NASMFLAGS	=	-f elf64
LINKER		=	ld

$(EXEC): $(OBJ)
	$(LINKER) -o $@ $^

all: $(EXEC)

%.o: %.s
	$(NASM) $(NASMFLAGS) -o $@ $<

clean:
	rm -f $(OBJ)

fclean: clean
	rm -rf $(EXEC)

re: fclean all

.PHONY: all clean fclean re
