package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/redis/go-redis/v9"
)

type Config struct {
	Port        string
	RedisURL    string
	WorkerCount int
	Mode        string // "api", "worker", or "both"
	StoragePath string
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}

func loadConfig() Config {
	return Config{
		Port:        getEnv("PORT", "8080"),
		RedisURL:    getEnv("REDIS_URL", "redis://localhost:6379"),
		WorkerCount: getEnvInt("WORKER_COUNT", 10),
		Mode:        getEnv("MODE", "both"),
		StoragePath: getEnv("STORAGE_PATH", "./output"),
	}
}

type Task struct {
	ID        string    `json:"id"`
	FilePath  string    `json:"file_path"`
	JobID     string    `json:"job_id"`
	Retry     int       `json:"retry"`
	CreatedAt time.Time `json:"created_at"`
}

type Job struct {
	ID             string     `json:"id"`
	Status         string     `json:"status"` // pending, processing, completed, failed
	TotalFiles     int        `json:"total_files"`
	ProcessedFiles int        `json:"processed_files"`
	FailedFiles    int        `json:"failed_files"`
	CreatedAt      time.Time  `json:"created_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}

type TaskManager struct {
	client *redis.Client
}

func NewTaskManager(redisURL string) (*TaskManager, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}

	client := redis.NewClient(opt)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	return &TaskManager{client: client}, nil
}

func (tm *TaskManager) EnqueueTask(ctx context.Context, task Task) error {
	data, err := json.Marshal(task)
	if err != nil {
		return err
	}

	return tm.client.LPush(ctx, "pdf_tasks", data).Err()
}

func (tm *TaskManager) DequeueTask(ctx context.Context) (*Task, error) {
	result, err := tm.client.BRPop(ctx, 30*time.Second, "pdf_tasks").Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}

	var task Task
	if err := json.Unmarshal([]byte(result[1]), &task); err != nil {
		return nil, err
	}

	return &task, nil
}

func (tm *TaskManager) UpdateJobStatus(ctx context.Context, jobID string, update map[string]interface{}) error {
	return tm.client.HMSet(ctx, fmt.Sprintf("job:%s", jobID), update).Err()
}

func (tm *TaskManager) GetJobStatus(ctx context.Context, jobID string) (*Job, error) {
	result, err := tm.client.HGetAll(ctx, fmt.Sprintf("job:%s", jobID)).Result()
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("job not found")
	}

	job := &Job{}
	if err := mapToStruct(result, job); err != nil {
		return nil, err
	}

	return job, nil
}

func (tm *TaskManager) Close() error {
	return tm.client.Close()
}

type APIServer struct {
	config      Config
	taskManager *TaskManager
	processor   *PDFProcessor
}

func NewAPIServer(config Config) (*APIServer, error) {
	taskManager, err := NewTaskManager(config.RedisURL)
	if err != nil {
		return nil, err
	}

	processor := NewPDFProcessor(config.StoragePath)

	return &APIServer{
		config:      config,
		taskManager: taskManager,
		processor:   processor,
	}, nil
}

func (s *APIServer) Start(ctx context.Context) error {
	router := mux.NewRouter()

	// API routes
	router.HandleFunc("/health", s.handleHealth).Methods("GET")
	router.HandleFunc("/upload", s.handleUpload).Methods("POST")
	router.HandleFunc("/job/{id}", s.handleJobStatus).Methods("GET")
	router.HandleFunc("/jobs", s.handleListJobs).Methods("GET")

	router.PathPrefix("/results/").Handler(
		http.StripPrefix("/results/", http.FileServer(http.Dir(s.config.StoragePath))),
	).Methods("GET")

	server := &http.Server{
		Addr:    ":" + s.config.Port,
		Handler: router,
	}

	go func() {
		log.Printf("API server starting on port %s", s.config.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return server.Shutdown(shutdownCtx)
}

func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
	})
}

func (s *APIServer) handleUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(100 << 20); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		http.Error(w, "No files provided", http.StatusBadRequest)
		return
	}

	jobID := generateID()

	job := Job{
		ID:         jobID,
		Status:     "pending",
		TotalFiles: len(files),
		CreatedAt:  time.Now(),
	}

	ctx := r.Context()
	if err := s.saveJob(ctx, job); err != nil {
		http.Error(w, "Failed to create job", http.StatusInternalServerError)
		return
	}

	tempDir := fmt.Sprintf("/tmp/pdf_upload_%s", jobID)
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		http.Error(w, "Failed to create temp directory", http.StatusInternalServerError)
		return
	}

	tasksEnqueued := 0
	for _, fileHeader := range files {
		file, err := fileHeader.Open()
		if err != nil {
			continue
		}
		defer file.Close()

		tempFilePath := fmt.Sprintf("%s%s", tempDir, fileHeader.Filename)
		if err := saveUploadedFile(file, tempFilePath); err != nil {
			continue
		}

		task := Task{
			ID:        generateID(),
			FilePath:  tempFilePath,
			JobID:     jobID,
			CreatedAt: time.Now(),
		}

		if err := s.taskManager.EnqueueTask(ctx, task); err != nil {
			log.Printf("Failed to enqueue task: %v", err)
			continue
		}

		tasksEnqueued++
	}

	s.taskManager.UpdateJobStatus(ctx, jobID, map[string]interface{}{
		"total_files": tasksEnqueued,
		"status":      "processing",
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"job_id":      jobID,
		"total_files": tasksEnqueued,
		"status":      "processing",
	})
}

func (s *APIServer) handleJobStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	jobID := vars["id"]

	job, err := s.taskManager.GetJobStatus(r.Context(), jobID)
	if err != nil {
		http.Error(w, "Job not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(job)
}

func (s *APIServer) handleListJobs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "List jobs endpoint - implement based on your needs",
	})
}

func (s *APIServer) saveJob(ctx context.Context, job Job) error {
	jobData := map[string]interface{}{
		"id":              job.ID,
		"status":          job.Status,
		"total_files":     job.TotalFiles,
		"processed_files": job.ProcessedFiles,
		"failed_files":    job.FailedFiles,
		"created_at":      job.CreatedAt.Format(time.RFC3339),
	}

	return s.taskManager.UpdateJobStatus(ctx, job.ID, jobData)
}

type WorkerPool struct {
	config      Config
	taskManager *TaskManager
	processor   *PDFProcessor
}

func NewWorkerPool(config Config) (*WorkerPool, error) {
	taskManager, err := NewTaskManager(config.RedisURL)
	if err != nil {
		return nil, err
	}

	processor := NewPDFProcessor(config.StoragePath)

	return &WorkerPool{
		config:      config,
		taskManager: taskManager,
		processor:   processor,
	}, nil
}

func (wp *WorkerPool) Start(ctx context.Context) error {
	log.Printf("Starting worker pool with %d workers", wp.config.WorkerCount)

	for i := 0; i < wp.config.WorkerCount; i++ {
		go wp.worker(ctx, i)
	}

	<-ctx.Done()
	log.Println("Worker pool shutting down")
	return nil
}

func (wp *WorkerPool) worker(ctx context.Context, workerID int) {
	log.Printf("Worker %d started", workerID)

	for {
		select {
		case <-ctx.Done():
			log.Printf("Worker %d stopping", workerID)
			return
		default:
			task, err := wp.taskManager.DequeueTask(ctx)
			if err != nil {
				log.Printf("Worker %d: Error dequeuing task: %v", workerID, err)
				time.Sleep(5 * time.Second)
				continue
			}

			if task == nil {
				// No tasks available, continue polling
				continue
			}

			log.Printf("Worker %d: Processing task %s", workerID, task.ID)

			if err := wp.processTask(ctx, task); err != nil {
				log.Printf("Worker %d: Error processing task %s: %v", workerID, task.ID, err)
				wp.handleTaskFailure(ctx, task, err)
			} else {
				log.Printf("Worker %d: Successfully processed task %s", workerID, task.ID)
				wp.handleTaskSuccess(ctx, task)
			}
		}
	}
}

func (wp *WorkerPool) processTask(ctx context.Context, task *Task) error {
	// Process the PDF file
	outputPath, err := wp.processor.ProcessPDF(task.FilePath)
	if err != nil {
		return fmt.Errorf("failed to process PDF: %w", err)
	}

	log.Printf("Task %s: Generated output file: %s", task.ID, outputPath)

	// Clean up temp file
	if err := os.Remove(task.FilePath); err != nil {
		log.Printf("Warning: Failed to remove temp file %s: %v", task.FilePath, err)
	}

	return nil
}

func (wp *WorkerPool) handleTaskSuccess(ctx context.Context, task *Task) {
	wp.taskManager.client.HIncrBy(ctx, fmt.Sprintf("job:%s", task.JobID), "processed_files", 1)

	job, err := wp.taskManager.GetJobStatus(ctx, task.JobID)
	if err != nil {
		log.Printf("Error getting job status: %v", err)
		return
	}

	if job.ProcessedFiles+job.FailedFiles >= job.TotalFiles {
		now := time.Now()
		wp.taskManager.UpdateJobStatus(ctx, task.JobID, map[string]interface{}{
			"status":       "completed",
			"completed_at": now.Format(time.RFC3339),
		})
	}
}

func (wp *WorkerPool) handleTaskFailure(ctx context.Context, task *Task, err error) {
	wp.taskManager.client.HIncrBy(ctx, fmt.Sprintf("job:%s", task.JobID), "failed_files", 1)

	if task.Retry < 3 {
		task.Retry++
		if retryErr := wp.taskManager.EnqueueTask(ctx, *task); retryErr != nil {
			log.Printf("Failed to retry task %s: %v", task.ID, retryErr)
		}
		return
	}

	job, err := wp.taskManager.GetJobStatus(ctx, task.JobID)
	if err != nil {
		log.Printf("Error getting job status: %v", err)
		return
	}

	if job.ProcessedFiles+job.FailedFiles >= job.TotalFiles {
		status := "completed"
		if job.FailedFiles > 0 {
			status = "completed_with_errors"
		}

		now := time.Now()
		wp.taskManager.UpdateJobStatus(ctx, task.JobID, map[string]interface{}{
			"status":       status,
			"completed_at": now.Format(time.RFC3339),
		})
	}
}

func main() {
	var mode = flag.String("mode", "", "Run mode: api, worker, or both")
	flag.Parse()

	config := loadConfig()
	if *mode != "" {
		config.Mode = *mode
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutdown signal received")
		cancel()
	}()

	switch config.Mode {
	case "api":
		server, err := NewAPIServer(config)
		if err != nil {
			log.Fatalf("Failed to create API server: %v", err)
		}

		if err := server.Start(ctx); err != nil {
			log.Fatalf("API server error: %v", err)
		}

	case "worker":
		pool, err := NewWorkerPool(config)
		if err != nil {
			log.Fatalf("Failed to create worker pool: %v", err)
		}

		if err := pool.Start(ctx); err != nil {
			log.Fatalf("Worker pool error: %v", err)
		}
	case "both":
		// Start both API server and worker pool
		server, err := NewAPIServer(config)
		if err != nil {
			log.Fatalf("Failed to create API server: %v", err)
		}

		pool, err := NewWorkerPool(config)
		if err != nil {
			log.Fatalf("Failed to create worker pool: %v", err)
		}

		go func() {
			if err := server.Start(ctx); err != nil {
				log.Printf("API server error: %v", err)
				cancel()
			}
		}()

		if err := pool.Start(ctx); err != nil {
			log.Fatalf("Worker pool error: %v", err)
		}

	default:
		log.Fatalf("Invalid mode: %s. Use 'api', 'worker', or 'both'", config.Mode)
	}
}

//utils

func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func mapToStruct(m map[string]string, v interface{}) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func saveUploadedFile(src multipart.File, dst string) error {
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, src)
	return err
}
