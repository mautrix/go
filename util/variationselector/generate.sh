#!/bin/bash
echo -e "$(
	curl -s https://www.unicode.org/Public/15.0.0/ucd/emoji/emoji-variation-sequences.txt \
	| grep FE0F \
	| awk '{ printf("\\U%8s\n", $1) }' \
	| sed 's/ /0/g'
)" | jq -RcM '[inputs]' > emojis-with-variations.json

# Why does this need a \n at the beginning to avoid eating the first emoji?!?!
echo -e "\n$(
	curl -s https://unicode.org/Public/emoji/15.0/emoji-test.txt \
	| grep '; fully-qualified' \
	| grep FE0F \
	| sed -E 's/\s+;.*//g' \
	| awk '{ for (i = 1; i <= NF; i++) {printf("\\U%8s", $i) }; printf("\n") }' \
	| sed 's/ /0/g'
)" | jq -RcM '[inputs]' > fully-qualified-variations.json
