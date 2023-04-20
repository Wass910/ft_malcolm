#include "../inc/ft_malcolm.h"

void	*ft_memcpy(void *dest, const void *src, size_t n)
{
	const char	*tmp;
	char		*fin;
	int			i;

	if (!dest && !src)
		return (NULL);
	tmp = (const char *)src;
	fin = (char *)dest;
	i = 0;
	while (n > 0)
	{
		fin[i] = tmp[i];
		i++;
		n--;
	}
	return (fin);
}

char *delete_double_point(char *mac)
{
    char *str = malloc(sizeof(char) * 13);
    int i = 0, j = 0;

    while(mac[i])
    {
        if (mac[i] != ':')
        {
            str[j] = mac[i];
            j++;
        }
        i++;
    }
    str[j] = '\0';
    return str;
}

void str_to_ip(const char *str, unsigned char *ip) 
{
    int num = 0, i = 0, j = 0;
    while (str[j] != '\0') {
        if (str[j] == '.') {
            ip[i++] = (unsigned char) num;
            num = 0;
        } else {
            num = num * 10 + (str[j] - '0');
        }
        j++;
    }
    ip[i] = (unsigned char) num;
}

void    exit_msg(char *str)
{
    printf("%s\n", str);
    exit(1);
}

int		ft_strncmp(const char *s1, const char *s2, size_t n)
{
	if (n <= 0)
		return (0);
	while (n > 1 && (*s1 != '\0' && *s2 != '\0') && *s1 == *s2)
	{
		s1++;
		s2++;
		n--;
	}
	return ((unsigned char)*s1 - (unsigned char)*s2);
}

int		ft_strlen(char *s)
{
	int i;

	i = 0;
	while (s[i] != '\0')
	{
		i++;
	}
	return (i);
}

int		ft_isalnum(int c)
{
	if (c < 48 || c > 122)
        return 1;
	if (c > 57 && c < 97)
        return 1;
	return (0);
}

int		ft_isdigit(int c)
{
	if (c >= 48 && c <= 57)
		return (0);
	return (1);
}