FROM python:3.11-slim

WORKDIR /app

# basic deps
RUN pip install --no-cache-dir --upgrade pip

# copy source
COPY . .

# default command (we'll replace once moltbot code exists)
CMD ["python", "-c", "print('container alive')"]
