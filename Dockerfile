FROM python:3.11-slim

# Install necessary dependencies, including Chrome for nodriver
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    unzip \
    curl \
    # Required for python-multipart and other C dependencies
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Google Chrome Stable
RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/googlechrome-linux-keyring.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/googlechrome-linux-keyring.gpg] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list \
    && apt-get update \
    && apt-get install -y google-chrome-stable \
    && rm -rf /var/lib/apt/lists/*

# Set up a working directory
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . /app

# Expose the API port
EXPOSE 7860

# Environment variables to run Chrome headlessly in nodriver and to identify docker env
ENV PYTHONUNBUFFERED=1
ENV IS_DOCKER=1
ENV PORT=7860

# Command to run the Fast API app using uvicorn directly
CMD ["python", "main.py"]
