#!/bin/bash
echo -e "$(
	curl -s https://www.unicode.org/Public/14.0.0/ucd/emoji/emoji-variation-sequences.txt \
	| grep FE0F \
	| awk '{ printf("\\U%8s\n", $1) }' \
	| sed 's/ /0/g'
)" | jq -RcM '[inputs]' > emojis-with-variations.json
