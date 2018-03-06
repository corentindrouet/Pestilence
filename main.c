#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>

char *encrypt_zone(void *zone, int size);
//void	*get_random_key(void);

int		file_size(int fd) {
	int off;

	lseek(fd, 0, SEEK_SET);
	off = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	return (off);
}

/*void	*get_random_key(void)
{  
    unsigned char *key;
    int i;

    key = malloc(256 + 1);
    i = 0;
    while (i < 256) {
        key[i] = i;
        i++;
    }
    key[256] = 0;
    return (key);
}
{
	void	*buffer;
	int		fd;
	int		numberRandomBytesReaded;

	numberRandomBytesReaded = 0;
	if ((fd = open("/dev/urandom", O_RDONLY)) == -1)
		return (NULL);
	if (!(buffer = malloc(256 + 1)))
		return (NULL);
	bzero(buffer, 256 + 1);
	while (numberRandomBytesReaded < 256)
	{
		read(fd, (buffer + numberRandomBytesReaded), 256 - numberRandomBytesReaded);
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

unsigned char	*encrypt_zone(char *zone, size_t size, unsigned char *key)
{
//	unsigned char	*key;
	int				tab[256];
	int				i;
	int				j;
	size_t			k;

	if (!zone || !size || !key)//!(key = get_random_key(256)))
		return (0);
	i = -1;
//	printf("Encryption key :\n%s\n", key);
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
	unsigned char *key;// = get_random_key();

	key = encrypt_zone(mmap_to_encrypt, fd_to_encrypt_size);
	write(fd_encrypted, key, 256);
	write(fd_encrypted, mmap_to_encrypt, fd_to_encrypt_size);
	munmap(mmap_to_encrypt, fd_to_encrypt_size);
	close(fd_to_encrypt);
	close(fd_encrypted);
//    free(key);
	munmap(key, 256);
	return (0);
}
