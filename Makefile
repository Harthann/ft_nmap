# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: nieyraud <nieyraud@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2022/02/23 16:28:15 by nieyraud          #+#    #+#              #
#    Updated: 2022/02/23 11:10:14 by nieyraud         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

#===================#
#		COLOR		#
#===================#

rose=\033[1;31m
violetfonce=\033[0;35m
violetclair=\033[1;35m
neutre=\033[0m
cyanfonce=\033[0;36m
cyanclair=\033[1;36m
vertfonce=\033[0;32m
vertclair=\033[1;32m
rouge=\033[31m

#===================#
#		SOURCES		#
#===================#

include files.mk

#===========================#
#		DIRCTORIES PATH		#
#===========================#

SPATH = ${shell find srcs -type d}
OBJ_PATH = objs
vpath %.c $(foreach dir, $(SPATH), $(dir))

# If project contains ASM files
#vpath %.s $(foreach dir, $(SPATH), $(dir))

#===============================#
#		FILES	VARIABLE		#
#===============================#

#SRCS	= $(addprefix ${SPATH}, ${SRC_FILE})
#SRCS_ASM = $(addprefix ${SPATH}, $(SRC_ASM))
OBJ		= ${addprefix ${OBJ_PATH}/, ${SRC_FILE:%.c=%.o}} \
			${addprefix ${OBJ_PATH}/, ${SRC_ASM:%.s=%.o}}

#===================#
#		FLAGS		#
#===================#

FLAGS = -Wall -Werror -Wextra -MMD -MP 
DEBUG = -g3
SAN = -g3 -fsanitize=address
OPT_FLAGS = -flto

ifeq ($(strip $(shell uname)),Darwin)
ECHO_FLAGS=-e
else
ECHO_FLAGS=
endif

#===========================#
#		BULD RULES			#
#===========================#

all : $(NAME)

$(NAME) : ${OBJ} 
	@echo $(ECHO_FLAGS) "${vertclair}Creating ${NAME}"
	@gcc ${FLAGS} ${OPT_FLAGS} -I include  ${OBJ} -o ${NAME}
	@echo $(ECHO_FLAGS) "${vertclair}[$(NAME) is ready]"

debug: extend_flags re

extend_flags:
	$(eval FLAGS += $(DEBUG))

${OBJ_PATH}/%.o: %.c
	@mkdir -p ${OBJ_PATH}
	@echo $(ECHO_FLAGS) "${cyanfonce}Compiling ${notdir $(basename $@)}"
	@gcc $(FLAGS) -c -o $@ -I include/ $<
-include $(OBJ:.o=.d)


#	In case of asm sources
$(OBJ_PATH)/%.o: %.s
	@echo $(ECHO_FLAGS) "${cyanfonce}Compiling ${notdir $(basename $@)}"
	@nasm -f elf64 $< -o $@ 

#========================#
#=		CLEANING RULES	=#
#========================#

clean :
	@echo $(ECHO_FLAGS) "${rouge}Removing objects files"
	@rm -rf ${OBJ_PATH}

fclean : clean
	@echo $(ECHO_FLAGS) "${rose}Removing ${NAME}"
	@rm -f $(NAME) ${LIBS}
	

re : fclean all

.PHONY : all clean fclean re
