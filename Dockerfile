FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PANEL_DATA_DIR=/data
WORKDIR /app
COPY requirements.txt requirements.lock ./
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 10001 --create-home panel && mkdir /data && chown panel:panel /data
COPY --chown=panel:panel app ./app
COPY --chown=panel:panel static ./static
USER panel
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=3)"
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
