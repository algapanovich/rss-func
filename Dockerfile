# Step 1: Base Image
FROM python:3.12-slim

# Step 2: Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Step 3: Set the working directory
WORKDIR /app

# Step 4: Install Dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Step 5: Copy Your Application Code
COPY . .

# Step 6: Define the command to run your script
# This now directly calls your Python script.
# NOTE: Assuming rss_feed.py is the main script to run. Adjust if necessary.
CMD ["python", "rss_syphon/rss_feed.py"]