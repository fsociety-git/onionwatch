FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir -e .
COPY config.toml categories.toml ./
ENTRYPOINT ["dwcollector"]
CMD ["stats"]
