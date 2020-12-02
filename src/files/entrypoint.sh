#!/bin/ash
# docker container entry point

RED="\e[31m"
BLUE="\e[34m"
GREEN="\e[32m"
NORMAL="\e[0m"


echo -e "${BLUE}
█████████████████████████████████████████████████████████████████████████████
█████████████████████████████████████████████████████████████████████████████${NORMAL}
██ ███ █ ▄▄▀██ ▄▄▀█ ▄▄▀██████████ ▄▄ ██ ███ ██ ▀██ ██ ▄▄▄██ ▄▄▀██ ▄▄▀██ ▄▄▀██
██▄▀▀▀▄█ ▀▀ ██ ▀▀▄█ ▀▀ ███▀ ▀████ ▀▀ ██ █ █ ██ █ █ ██ ▄▄▄██ ██ ██ █████ ▀▀▄██${RED}
████ ███ ██ ██ ██ █ ██ ████▄█████ █████▄▀▄▀▄██ ██▄ ██ ▀▀▀██ ▀▀ ██ ▀▀▄██ ██ ██
█████████████████████████████████████████████████████████████████████████████
█████████████ ███ ██ ▄▄▄ ██ ▄▄▀██ █▀▄██ ▄▄▄ ██ ██ ██ ▄▄3 ██ ▄▄ ██████████████${NORMAL}
█████████████ █ █ ██ ███ ██ ▀▀▄██ ▄▀███▄▄▄▀▀██ ▄▄ ██ █x█ ██ ▀▀ ██████████████
█████████████▄▀▄▀▄██ ▀▀▀ ██ ██ ██ ██ ██ ▀▀▀ ██ ██ ██ 0▀▀ ██ █████████████████${BLUE}
█████████████████████████████████████████████████████████████████████████████
█████████████████████████████████████████████████████████████████████████████${NORMAL}
"

#set -x
hostname workshop && echo -n "workshop" > /etc/hostname
# we don't need you
rm -f /rules/test_rule
# disable ASLR
sysctl -w kernel.randomize_va_space=0 >/dev/null
# setup vim syntax for Yara
cat <<VIMRC >> /root/.vimrc
set ts=4 sw=4 sts=4 ai et sta
autocmd BufNewFile,BufRead *.yar,*.yara setlocal filetype=yara
VIMRC

# build dummy malware
(
  cd /malware/dummy && make -s
  [ ! -f dummy ] && {
    exec 1>&2
    echo -e "${RED}"
    echo "!!! Something went wrong compiling the dummy malware !!!"
    echo "!!!             Contact the workshop admins          !!!"
    echo -e "${NORMAL}"
    return 1
  }
  return 0
)
[ $? -gt 0 ] && exit 1

# WARNING: extracting malware!!!
(
  cd /malware && for f in *.zip; do unzip -P pwnedcr ${f}  >/dev/null 2>&1; done
)

export PS1='\h:\w \$ '
echo -e "${GREEN}LETS GO!${NORMAL}"
# jmp to shell
/bin/ash
