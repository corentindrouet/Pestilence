#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <elf.h>

extern int _crc32(void *mem, unsigned int len);

size_t	file_size(int fd)
{
	off_t	off;

	if (fd < 0)
		return (0);
	lseek(fd, 0, SEEK_SET);
	off = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	if (off == -1)
		return (0);
	return ((size_t)off);
}

void patch_checksum_infos(void *mmaped) {
	unsigned int checksum;
	Elf64_Ehdr *header;
	Elf64_Phdr *seg;
	void *p_vaddr;
	int size;
	int i;
	
	header = mmaped;
	seg = mmaped + header->e_phoff;

	i = 0;
	while (i < header->e_phnum) {
		if (seg[i].p_type == PT_LOAD)
			break ;
		i++;
	}

	p_vaddr = (void*)seg[i].p_vaddr;
	size = seg[i].p_filesz - 16;
	checksum = _crc32(mmaped + seg[i].p_offset, size);
	*(long*)(mmaped + seg[i].p_offset + size) = (long)p_vaddr;
	*(int*)(mmaped + seg[i].p_offset + size + 8) = size;
	*(unsigned int*)(mmaped + seg[i].p_offset + size + 12) = checksum;
}

void patch_table_offset(void *mmaped) {
	Elf64_Ehdr	*header;
	Elf64_Phdr *seg;
	Elf64_Shdr *sec;
	Elf64_Shdr *sec_sym;
	Elf64_Sym 	*sym;
	unsigned char *text_sec;
	int text_size;
	unsigned long text_base_addr;
	int i;
	unsigned long _table;
	unsigned long _o_entry;
	unsigned long _start;
	unsigned long _table_offset;
	char *file_content;
	char *strtab;
	int nb;

	header = mmaped;
	seg = mmaped + header->e_phoff;
	sec = mmaped + header->e_shoff;

	file_content = mmaped + sec[header->e_shstrndx].sh_offset;

	i = 0;
	while (i < header->e_shnum) {
		if (sec->sh_type == SHT_SYMTAB) {
			sec_sym = sec;
			sym = mmaped + sec->sh_offset;
		} else if (sec->sh_type == SHT_STRTAB && !strcmp(file_content + sec->sh_name, ".strtab")) {
			strtab = mmaped + sec->sh_offset;
		} else if (sec->sh_type == SHT_PROGBITS && !strcmp(file_content + sec->sh_name, ".text")) {
			text_sec = mmaped + sec->sh_offset;
			text_size = sec->sh_size;
			text_base_addr = sec->sh_addr;
		}
		sec++;
		i++;
	}

	i = 0;
	while (i < sec_sym->sh_size) {
		if (!strcmp(strtab + sym->st_name, "_table_offset")) {
			_table = sym->st_value;
		} else if (!strcmp(strtab + sym->st_name, "_o_entry")) {
			_o_entry = sym->st_value;
		} else if (!strcmp(strtab + sym->st_name, "_start")) {
			_start = sym->st_value;
		}
		i += sym->st_size + sizeof(Elf64_Sym);
		sym = (void*)sym + sym->st_size + sizeof(Elf64_Sym);
	}
	_table_offset = _table - _o_entry;
	_table_offset += (unsigned long)text_sec;
	_start = _start - _o_entry;
	_start += (unsigned long)text_sec;

	i = _start - (unsigned long)text_sec;
	text_size -= 4;
	nb = 0;
	while (i < text_size) {
		if (text_sec[i] == 0x90 && (*((unsigned int*)(text_sec + i + 1)) == 0x90909090)) {
			*(int*)_table_offset = (int)((unsigned long)(text_sec + i) - _start);
			_table_offset += 4;
			i += 4;
			nb++;
			if (nb == 32)
				break ;
		}
		i++;
	}
	printf("%d\n", nb);
}

int main(void) {
	int fd;
	size_t fd_size;
	void *mmaped;

	fd = open("./pestilence", O_RDWR);
	fd_size = file_size(fd);
	mmaped = mmap(0, fd_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	patch_table_offset(mmaped);
	patch_checksum_infos(mmaped);
	munmap(mmaped, fd_size);
	close(fd);
}
