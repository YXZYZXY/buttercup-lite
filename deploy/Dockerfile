FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

COPY requirements.txt .
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        binutils \
        clang \
        llvm \
        llvm-dev \
        libclang-rt-19-dev \
        cmake \
        git \
        zip \
        unzip \
        file \
        tshark \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r requirements.txt
RUN python3 - <<'PY'
import tree_sitter_language_pack as lp

for lang in ["c", "cpp"]:
    try:
        lp.get_language(lang)
        print(f"preloaded {lang}")
    except Exception as exc:
        print(f"skip {lang}: {exc}")
PY

COPY . .
