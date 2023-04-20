SRC=    srcs/malcolm.c srcs/utils.c srcs/ft_check.c srcs/verbose.c \

OBJ_DIR 		= obj

OBJS			= $(SRC:.c=.o)

NAME			= ft_malcolm

CFLAGS			= -Wall -Wextra -Werror -g

RM				= rm -rf

CC				= gcc


$(OBJ_DIR)/%.o : $(SRC)/%.c
				$(CC) $(CFLAGS) -c $< -o $@
				

$(NAME):		create_dirs $(OBJS)
				$(CC) $(CFLAGS) $(OBJS) -o $(NAME) -L.
				@mv srcs/*.o $(OBJ_DIR)

all:			$(NAME)

create_dirs:
				@mkdir -p $(OBJ_DIR)

clean:
				$(RM) $(OBJ_DIR)

fclean:			clean
				$(RM) $(NAME)

re:				fclean all

.PHONY:			all clean fclean c.o re 