
FROM debian:stable

# Install necessary system packages
RUN apt-get update && apt-get install -y --no-install-recommends     bash     sudo     debootstrap     schroot     python3     python3-pip     python3-venv     python3-debian     python3-apt     git     build-essential     gnupg     curl     libxml2-dev     libxslt1-dev     zlib1g-dev     mmdebstrap     zsh     && rm -rf /var/lib/apt/lists/*

# Set up sudo privileges
RUN echo 'ALL ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

# Set the working directory
WORKDIR /app

# Create a virtual environment
RUN python3 -m venv /app/venv

# Set the virtual environment path as the primary for all operations
ENV PATH="/app/venv/bin:$PATH"

# Optionally, add system site-packages to the PYTHONPATH
ENV PYTHONPATH="/usr/lib/python3/dist-packages:$PYTHONPATH"

# Upgrade pip to the latest version using the absolute path to ensure the correct pip is used
RUN /app/venv/bin/pip install --upgrade pip

# Install necessary Python libraries using the virtual environment’s pip
RUN /app/venv/bin/pip install requests beautifulsoup4 python-debian python-dateutil rstr google-auth httpx tenacity flask

# Copy all application files
COPY . /app

# Set permissions for the copied files
RUN chmod -R a+rX /app

# Ensure zsh is executable and set as the default shell
RUN chmod +x /bin/zsh
SHELL ["/bin/zsh", "-c"]

# Entry point
ENTRYPOINT ["/bin/zsh"]
