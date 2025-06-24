FROM python:3.10

# Install dependencies and clone Nikto
RUN apt-get update && \
    apt-get install -y git perl curl libnet-ssleay-perl openssl && \
    git clone https://github.com/sullo/nikto.git /opt/nikto && \
    chmod +x /opt/nikto/program/nikto.pl && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy bot files
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Default run command
CMD ["python", "main.py"]
