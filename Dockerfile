FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# shroodler must be mounted or installed separately:
# docker run -v /usr/local/bin/shroodler:/usr/local/bin/shroodler ...
CMD ["python", "bot.py"]
