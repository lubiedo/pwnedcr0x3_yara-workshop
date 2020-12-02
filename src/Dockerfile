FROM blacktop/yara:latest

WORKDIR /root

RUN apk add --no-cache vim git unzip gcc make musl-dev gdb && \
  mkdir -p .vim/syntax
COPY files/yara.vim .vim/syntax/

COPY files/malware /malware
COPY files/rules /rules
COPY files/entrypoint.sh /entrypoint.sh

WORKDIR /

ENTRYPOINT ["/bin/ash", "/entrypoint.sh"]
