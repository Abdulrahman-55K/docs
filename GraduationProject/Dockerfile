FROM python:3.11-slim

# Install system utilities needed for building packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create a dedicated, low-privileged security user group
RUN groupadd -r djangogroup && useradd -r -g djangogroup djangouser

WORKDIR /app

# Install dependencies (Make sure 'gunicorn' and 'whitenoise' are in your requirements.txt)
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source code
COPY . /app/

# AUTOMATION LAYER: Compile static layout assets during the container build
RUN SECRET_KEY=dummy-build-key-only python manage.py collectstatic --noinput

# =========================================================================
# CRITICAL FIX: Pre-create and force permission ownership on ALL paths 
# that will be used by your Docker-Compose volumes.
# =========================================================================
RUN mkdir -p /app/media/quarantine /app/logs /app/media/models /app/media/yara_rules /app/db_data \
    && chown -R djangouser:djangogroup /app/ /app/media/quarantine /app/logs /app/media/models /app/media/yara_rules /app/db_data \
    && chmod -R 775 /app/media/quarantine /app/logs /app/media/models /app/media/yara_rules /app/db_data

# Switch context entirely away from root for application runtime
USER djangouser

EXPOSE 8000

# CHANGED: Standard Output execution to bypass log capturing blocks
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--access-logfile", "-", "--error-logfile", "-", "core.wsgi:application"]