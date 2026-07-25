# FROM python:3.12-slim

# WORKDIR /app

# COPY requirements.txt .
# RUN pip install --no-cache-dir -r requirements.txt

# COPY . .

# EXPOSE 8080
# CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]




FROM python:3.12-slim

# The recommended way to install uv in Docker is to pull the compiled binary
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Copy dependency definition files first to leverage Docker layer caching
COPY pyproject.toml ./ 
# COPY uv.lock ./  # Uncomment this line if you are also generating a uv.lock file

# Install dependencies directly from pyproject.toml into the system environment
RUN uv pip install --system --no-cache -r pyproject.toml

# Copy the rest of the application code
COPY . .

EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]