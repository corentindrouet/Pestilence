EXEC		=	pestilence
SRC			=	famine.s \
                start_infect.s \
				fork.s \
				update_mmaped_file.s \
				encrypt.s \
				treat_file.s \
				depacker.s
OBJ			=	$(SRC:.s=.o)
NASM		=	nasm
NASMFLAGS	=	-f elf64
LINKER		=	ld

$(EXEC): $(OBJ)
	$(info Compiling $(EXEC))
	$(LINKER) -o $@ $^

all: $(EXEC)

%.o: %.s
	$(info Compiling $< into $@ ...)
	@$(NASM) $(NASMFLAGS) -o $@ $<

clean:
	$(info Cleaning ./ ...)
	rm -f $(OBJ)
	$(info Done !)

fclean: clean
	$(info Cleaning ./ ...)
	@rm -rf $(EXEC)
	$(info Done !)

re: fclean all

.PHONY: all clean fclean re