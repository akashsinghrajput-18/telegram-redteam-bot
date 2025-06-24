FROM python:3.10

# Update apt and install perl, curl, git
RUN apt-get update && apt-get install -y perl curl git && rm -rf /var/lib/apt/lists/*

# Clone nikto repo from GitHub
RUN git clone https://github.com/sullo/nikto.git /opt/nikto

# Add nikto to PATH
ENV PATH="/opt/nikto:${PATH}"

# Set working directory inside container
WORKDIR /app

# Copy all files (including your bot scripts and requirements.txt)
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Default command to run your bot
CMD ["python", "main.py"]
