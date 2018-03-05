#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>

char *encrypt_zone(void *zone, int size);

int		file_size(int fd) {
	int off;

	lseek(fd, 0, SEEK_SET);
	off = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	return (off);
}

/*void	*get_random_key(size_t size)
{
	void	*buffer;
	int		fd;
	int		numberRandomBytesReaded;

	numberRandomBytesReaded = 0;
	if ((fd = open("/dev/urandom", O_RDONLY)) == -1)
		return (NULL);
	if (!(buffer = malloc(size + 1)))
		return (NULL);
	bzero(buffer, size + 1);
	while (numberRandomBytesReaded < 256)
	{
		read(fd, (buffer + numberRandomBytesReaded), size - numberRandomBytesReaded);
		numberRandomBytesReaded = strlen(buffer);
	}
	close(fd);
	return (buffer);
}

void	swap(int *a, int *b)
{
	*a = *a + *b;
	*b = *a - *b;
	*a = *a - *b;
}

unsigned char	*encrypt_zone(char *zone, size_t size)
{
	unsigned char	*key;
	int				tab[256];
	int				i;
	int				j;
	size_t			k;

	if (!zone || !size || !(key = get_random_key(256)))
		return (0);
	i = -1;
	printf("Encryption key :\n%s\n", key);
	while (++i < 256)
		tab[i] = i;
	i = -1;
	j = 0;
	while (++i < 256)
	{
		j = (j + tab[i] + key[i % 256]) % 256;
		swap(&(tab[i]), &(tab[j]));
	}
	i = 0;
	j = 0;
	k = 0;
	while (k < size)
	{
		i = (i + 1) % 256;
		j = (j + tab[i]) % 256;
		swap(&(tab[i]), &(tab[j]));
		j = (tab[i] + tab[j]) % 256;
		zone[k] = zone[k] ^ tab[j];
		k++;
	}
	return (key);
}*/

int main(int argc, char **argv) {
	int fd_to_encrypt = open(argv[1], O_RDONLY);
	int fd_encrypted = open(argv[2], O_RDWR);
	int fd_to_encrypt_size = file_size(fd_to_encrypt);
	char *mmap_to_encrypt = mmap(0, fd_to_encrypt_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd_to_encrypt, 0);
	char *key;

	key = encrypt_zone(mmap_to_encrypt, fd_to_encrypt_size);
	write(fd_encrypted, key, 256);
	write(fd_encrypted, mmap_to_encrypt, fd_to_encrypt_size);
	munmap(mmap_to_encrypt, fd_to_encrypt_size);
	close(fd_to_encrypt);
	close(fd_encrypted);
	munmap(key, 256);
	return (0);
}
