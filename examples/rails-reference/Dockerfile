FROM ruby:3.4-slim@sha256:c12225b6a73743f943530d9e610f4ae78e0dbcffdcf797b01522a55f7d25acb3
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libpq-dev git ca-certificates
WORKDIR /app
COPY Gemfile Gemfile.lock ./
RUN bundle config set frozen true && bundle install
COPY . .
ENV RAILS_ENV=development
CMD ["bundle", "exec", "puma", "-C", "config/puma.rb"]
