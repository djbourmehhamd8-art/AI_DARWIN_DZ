FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# run as an unprivileged user; /app/data (database, logs) is the only writable place
RUN useradd --system --no-create-home --uid 10001 darwin && mkdir -p /app/data && chown -R darwin /app/data
USER darwin
VOLUME ["/app/data"]
# healthy when the web panel answers /healthz (always healthy if the panel is disabled)
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os,urllib.request as u; p=os.environ.get('WEB_PANEL_PORT') or os.environ.get('PORT'); p and u.urlopen('http://127.0.0.1:%s/healthz'%p, timeout=4)"
CMD ["python", "main.py"]
