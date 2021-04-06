#!/bin/zsh

export JEKYLL_VERSION=latest
docker run --rm \
    --volume="`pwd`:/srv/jekyll" \
    -p 4000:4000 \
    -it jekyll/jekyll:$JEKYLL_VERSION \
    bash
