FROM python:3.13-slim
WORKDIR /arena
COPY challenge/runtime/worker.py /arena/worker.py
RUN useradd --create-home --uid 10001 arena && chmod 0555 /arena/worker.py
ENV RELEASE_SENTINEL_ARENA_CONTAINER=1
USER 10001:10001
ENTRYPOINT ["python", "/arena/worker.py"]
