#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
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

int main(void) {
	int fd;
	size_t fd_size;
	void *mmaped;
	unsigned int checksum;
	Elf64_Ehdr *header;
	Elf64_Phdr *seg;
	void *p_vaddr;
	int size;
	int i;

	fd = open("./pestilence", O_RDWR);
	fd_size = file_size(fd);
	mmaped = mmap(0, fd_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	
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

	munmap(mmaped, fd_size);
	close(fd);
}
