# PDF-Processor-Golang

A concurrent microservice to extract text from PDFs. Uploads are accepted via a REST API, queued in Redis, and processed by a horizontally scalable worker pool. Extracted text passes through a configurable quality assurance pipeline before being saved.

## Use Cases

- **LLM preprocessing** -- extract and clean text from bulk PDFs before ingestion into a vector database or language model pipeline
- **ETL pipelines** -- use as a document extraction service where PDFs are a raw data source feeding into a database or analytics system
- **Document processing at scale** -- batch extraction for high-volume environments (legal, insurance, finance) where raw PDF output needs to be clean and reliable before downstream use

## Architecture
 
```
Client -> API Server -> Redis Queue -> Worker Pool -> QA Engine -> Output
```
The API and worker roles are decoupled and run as separate containers, allowing independent scaling. The `MODE` environment variable controls whether a container runs as `api`, `worker`, or `both`.

## QA Pipeline
 
Each extracted PDF passes through `qa.go` before being saved:
 
- Unicode normalisation and control character removal
- Line filtering by minimum length and alphabetic character ratio
- Repeated header/footer detection and removal
- Stopword ratio, alpha ratio, and confidence scoring
- Configurable thresholds via `QAConfig`
Files below a confidence threshold of 0.7 are rejected.


## Quick Start
 
```bash
docker-compose up --build
```
 
This starts Redis, the API server, and two worker containers. A third worker (`pdf-worker-3`) is available under the `high-load` profile:
 
```bash
docker-compose --profile high-load up --build
```
 
Redis Commander (queue monitoring) is available under the `monitoring` profile on port `8081`.

## API
 
```bash
# Health check
curl http://localhost:8080/health
 
# Upload PDFs (one or more files)
curl -X POST http://localhost:8080/upload \
  -F "files=@document.pdf"
 
# Check job status
curl http://localhost:8080/job/{job_id}
 
# Download processed output
curl http://localhost:8080/results/{filename}.txt
```
 
## Configuration

| Variable | Default | Description |
|---|---|---|
| `MODE` | `both` | `api`, `worker`, or `both` |
| `PORT` | `8080` | API server port |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection URL |
| `WORKER_COUNT` | `10` | Goroutines per worker container |
| `STORAGE_PATH` | `./output` | Output directory for processed files |
 
## Stack
 
Go 1.24, Redis 7, Docker, Gin, gorilla/mux
