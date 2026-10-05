FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv
RUN useradd --create-home --uid 10001 gateway
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app ./app
COPY mock_upstream ./mock_upstream
RUN mkdir -p logs && chown -R gateway:gateway /srv
USER gateway
EXPOSE 8000
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
