FROM python:3.14.6-slim

# Security: run as non-root
RUN groupadd --gid 1000 appuser && useradd --uid 1000 --gid appuser --no-create-home appuser

WORKDIR /app

# Install dependencies before copying source (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Collect static files (no secrets needed at build time)
RUN DJANGO_SETTINGS_MODULE=config.settings.build python manage.py collectstatic --noinput

RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Production WSGI server — set all secrets via environment variables at runtime.
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "120"]
