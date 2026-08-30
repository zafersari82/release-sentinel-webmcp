FROM python:3.13-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir ".[cloud]"
ENV PORT=8080
CMD ["uvicorn", "release_sentinel.interfaces.api:app", "--host", "0.0.0.0", "--port", "8080"]
