# vulnfab as a container: docker run --rm -v "$PWD:/src:ro" vulnfab scan /src
FROM python:3.11-slim AS build
RUN pip install --no-cache-dir build
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m build --wheel --outdir /dist

FROM python:3.11-slim
RUN useradd --create-home --uid 10001 vulnfab
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl
USER vulnfab
ENV VULNFAB_CACHE_DIR=/tmp/vulnfab-cache
ENTRYPOINT ["vulnfab"]
CMD ["--help"]
