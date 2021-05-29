#!/bin/zsh

export JEKYLL_VERSION=4.1.0
docker run --rm \
    --volume="`pwd`:/srv/jekyll" \
    -p 4000:4000 \
    -it jekyll/jekyll:$JEKYLL_VERSION \
    bash


# modify `config.yml` and set local theme and comment out `remote_theme` when
# testing locally

# run `bundle install` followed by `bundle exec jekyll server --host 0.0.0.0`
# to test locally
