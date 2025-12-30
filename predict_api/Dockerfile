# Use an official lightweight Python image
FROM python:3.10-slim

# Set work directory
WORKDIR /app

# --- [QUAN TRỌNG] Cài đặt thư viện hệ thống bị thiếu cho LightGBM ---
# Thêm libgomp1 để sửa lỗi "cannot open shared object file"
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*
# --------------------------------------------------------------------

# Install dependencies
COPY requirements.txt /app/
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy project
COPY . /app/

# Expose port
EXPOSE 8000

# Command to run the API
CMD ["uvicorn", "predict_url:app", "--host", "0.0.0.0", "--port", "8000"]