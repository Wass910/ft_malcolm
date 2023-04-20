#include "../inc/ft_malcolm.h"

int     check_mac_adress(char *str)
{
    int i = 0, j = 0;
    if (ft_strlen(str) != 17)
        return 1 ;
    while (str[i] != '\0')
    {
        while (j < 2)
        {
            if (ft_isalnum(str[i]) == 1)
                return 1 ;
            j++;
            i++;
        }
        if (str[i] != '\0')
            break;
        else if (str[i] != ':')
            return 1 ;        
        i++;
        j = 0;
    }
    return 0;
}

void     check_ip_adress(char *str)
{
    in_addr_t addr = inet_addr(str);

    if (addr == INADDR_NONE) 
        exit_msg("Usage: invalid IP adress");
    return ;
}

void    check_arg(int argc, char **argv)
{
    if (getuid() != 0)
        exit_msg("Usage: sudo <ft_malcolm> [source mac address] [target ip] [target mac address] option : (-v)");
    if (argc != 4 )
    {
        if (argc == 5)
        {
            if (ft_strncmp((argv[4]), "-v", ft_strlen("-v")) == 0 && ft_strlen(argv[4]) == ft_strlen("-v"))
                all.verbose = 1;
            else 
                exit_msg("Usage: sudo <ft_malcolm> [source mac address] [target ip] [target mac address] option : (-v)");
        }
        else
            exit_msg("Usage: sudo <ft_malcolm> [source mac address] [target ip] [target mac address] option : (-v)");
    }
    if (check_mac_adress(argv[1]) == 1 )
        exit_msg("Usage: invalid MAC adress");
    check_ip_adress(argv[2]);
    return ;
}