#!/bin/sh
git grep -i 'g[a-zA-Z0-9]*Guid[ \t]*=[ \t]*{.*}[ \t]*}' \
	| sed 's/.*[^a-zA-Z0-9]\(g[a-zA-Z0-9]*Guid.*}[ \t]*}\)/\1/g'
