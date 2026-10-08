FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /opt/devsecops-scanner

COPY pyproject.toml README.md ./
COPY devsecops_scanner ./devsecops_scanner
RUN python -m pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 scanner

USER scanner
ENTRYPOINT ["devsecops-scanner"]
CMD ["scan", "--path", "/src", "--output", "/reports/security-report.html", "--fail-on", "high"]
