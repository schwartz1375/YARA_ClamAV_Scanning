# Use an official Python runtime as a parent image
FROM python:3.9-slim as base

# Set the working directory in the container
WORKDIR /app

# Set the maintainer label
LABEL maintainer="your-email@example.com"

# Install Yara
FROM base as yara
RUN apt-get update && apt-get install -y yara

# Install ClamAV
FROM yara as clamav
RUN apt-get update && apt-get install -y clamav clamav-daemon

# Install basic tools
RUN apt-get install -y git vim curl 

# Copy the current directory contents into the container at /app
COPY . /app

# Clone the Yara-Rules repository
RUN git clone https://github.com/Yara-Rules/rules.git 
