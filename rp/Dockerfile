FROM ruby:4.0.2-slim

# Install system dependencies
RUN apt-get update -qq && apt-get install -y \
  build-essential \
  libsqlite3-dev \
  libyaml-dev \
  git \
  tzdata \
  curl \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency files and install bundler/gems
COPY Gemfile Gemfile.lock ./
RUN gem install bundler && bundle install

# Copy application files
COPY . .

# Start puma
EXPOSE 3001
CMD ["bundle", "exec", "puma", "-C", "config/puma.rb", "-p", "3001"]
