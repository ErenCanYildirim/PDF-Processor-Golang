package main

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ledongthuc/pdf"
	"golang.org/x/text/unicode/norm"
)

// config for quality assurance
type QAConfig struct {
	MinLineLength        int     `json:"min_line_length"`
	MaxRepeatThreshold   float64 `json:"max_repeat_threshold"`
	MinStopwordRatio     float64 `json:"min_stopword_ratio"`
	MinWordLength        int     `json:"min_word_length"`
	MaxControlCharRatio  float64 `json:"max_control_char_ratio"`
	MinAlphaRatio        float64 `json:"min_alpha_ratio"`
	EnableLanguageFilter bool    `json:"enable_language_filter"`
}

// reasonable default values
func DefaultQAConfig() QAConfig {
	return QAConfig{
		MinLineLength:        3,
		MaxRepeatThreshold:   0.3,
		MinStopwordRatio:     0.1,
		MinWordLength:        2,
		MaxControlCharRatio:  0.05,
		MinAlphaRatio:        0.7,
		EnableLanguageFilter: true,
	}
}

// analysis results
type QualityReport struct {
	WordCount            int     `json:"word_count"`
	LineCount            int     `json:"line_count"`
	AvgWordsPerLine      float64 `json:"avg_words_per_line"`
	StopwordRatio        float64 `json:"stopword_ratio"`
	RepeatedContentRatio float64 `json:"repeated_content_ratio"`
	ControlCharRatio     float64 `json:"control_char_ratio"`
	AlphaRatio           float64 `json:"alpha_ratio"` //ratio of alphabetic characters
	HasTables            bool    `json:"has_tables"`
	Confidence           float64 `json:"confidence"`
	IsClean              bool    `json:"is_clean"`
}

// qa on extracted text
type QAEngine struct {
	config    QAConfig
	stopwords map[string]bool
	patterns  struct {
		headerFooter *regexp.Regexp
		tableMarker  *regexp.Regexp
		controlChars *regexp.Regexp
		whitespace   *regexp.Regexp
	}
}

func NewQAEngine(config QAConfig) *QAEngine {
	qa := &QAEngine{
		config:    config,
		stopwords: buildStopwordMap(),
	}

	// Compile regex patterns
	qa.patterns.headerFooter = regexp.MustCompile(`(?i)(page\s+\d+|header|footer|\d+\s*$|^\s*\d+)`)
	qa.patterns.tableMarker = regexp.MustCompile(`\t|\s{3,}|\|`)
	qa.patterns.controlChars = regexp.MustCompile(`[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]`)
	qa.patterns.whitespace = regexp.MustCompile(`\s+`)

	return qa
}

func (qa *QAEngine) ProcessText(raw string) (string, QualityReport, error) {
	if len(raw) == 0 {
		return "", QualityReport{}, fmt.Errorf("empty text input")
	}

	//Unicode normalization
	normalized := qa.normalizeUnicode(raw)

	//Remove control characters
	cleaned := qa.removeControlChars(normalized)

	//Split into lines and filter
	lines := strings.Split(cleaned, "\n")
	filteredLines := qa.filterLines(lines)

	//Remove repeated headers/footers
	deduped := qa.removeRepeatedElements(filteredLines)

	//Quality analysis
	result := strings.Join(deduped, "\n")
	report := qa.analyzeQuality(result)

	if !report.IsClean {
		return "", report, fmt.Errorf("text quality below threshold")
	}

	return result, report, nil
}

func (qa *QAEngine) normalizeUnicode(text string) string {
	return norm.NFC.String(text)
}

func (qa *QAEngine) removeControlChars(text string) string {
	var result strings.Builder
	result.Grow(len(text))

	for _, r := range text {
		if r == '\n' || r == '\t' || r == '\r' || !unicode.IsControl(r) {
			result.WriteRune(r)
		}
	}

	return result.String()
}

func (qa *QAEngine) filterLines(lines []string) []string {
	var filtered []string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if len(line) == 0 {
			continue
		}

		if len(line) < qa.config.MinLineLength {
			continue
		}

		if qa.getControlCharRatio(line) > qa.config.MaxControlCharRatio {
			continue
		}

		if qa.getAlphaRatio(line) < qa.config.MinAlphaRatio {
			continue
		}

		filtered = append(filtered, line)
	}

	return filtered
}

func (qa *QAEngine) removeRepeatedElements(lines []string) []string {
	if len(lines) > 3 {
		return lines
	}

	repeatedLines := make(map[string]int)
	for _, line := range lines {
		normalized := qa.patterns.whitespace.ReplaceAllString(strings.ToLower(line), " ")
		repeatedLines[normalized]++
	}

	threshold := int(float64(len(lines)) * qa.config.MaxRepeatThreshold)
	var filtered []string

	for _, line := range lines {
		normalized := qa.patterns.whitespace.ReplaceAllString(strings.ToLower(line), " ")
		if repeatedLines[normalized] <= threshold {
			filtered = append(filtered, line)
		}
	}

	return filtered
}

func (qa *QAEngine) analyzeQuality(text string) QualityReport {
	words := qa.extractWords(text)
	lines := strings.Split(text, "\n")

	report := QualityReport{
		WordCount: len(words),
		LineCount: len(lines),
	}

	if len(words) > 0 {
		report.AvgWordsPerLine = float64(len(words)) / float64(len(lines))
		report.StopwordRatio = qa.calculateStopwordRatio(words)
	}

	report.RepeatedContentRatio = qa.calculateRepeatedContentRatio(lines)
	report.ControlCharRatio = qa.getControlCharRatio(text)
	report.AlphaRatio = qa.getAlphaRatio(text)
	report.HasTables = qa.detectTables(text)
	report.Confidence = qa.calculateConfidence(report)
	report.IsClean = qa.isTextClean(report)

	return report
}

func (qa *QAEngine) extractWords(text string) []string {
	var words []string
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Split(bufio.ScanWords)

	for scanner.Scan() {
		word := strings.ToLower(strings.Trim(scanner.Text(), ".,!?;:\"'()[]{}"))
		if len(word) >= qa.config.MinWordLength && qa.isValidWord(word) {
			words = append(words, word)
		}
	}

	return words
}

func (qa *QAEngine) isValidWord(word string) bool {
	if len(word) == 0 {
		return false
	}

	alphaCount := 0
	for _, r := range word {
		if unicode.IsLetter(r) {
			alphaCount++
		}
	}

	return float64(alphaCount)/float64(len(word)) >= 0.5
}

func (qa *QAEngine) calculateStopwordRatio(words []string) float64 {
	if len(words) == 0 {
		return 0
	}

	stopwordCount := 0
	for _, word := range words {
		if qa.stopwords[word] {
			stopwordCount++
		}
	}

	return float64(stopwordCount) / float64(len(words))
}

func (qa *QAEngine) calculateRepeatedContentRatio(lines []string) float64 {
	if len(lines) <= 1 {
		return 0
	}

	lineCount := make(map[string]int)
	for _, line := range lines {
		normalized := qa.patterns.whitespace.ReplaceAllString(strings.ToLower(strings.TrimSpace(line)), " ")
		if len(normalized) > 0 {
			lineCount[normalized]++
		}
	}

	repeatedCount := 0
	for _, count := range lineCount {
		if count > 1 {
			repeatedCount += count - 1
		}
	}

	return float64(repeatedCount) / float64(len(lines))
}

func (qa *QAEngine) getControlCharRatio(text string) float64 {
	if len(text) == 0 {
		return 0
	}

	controlCount := 0
	for _, r := range text {
		if unicode.IsControl(r) && r != '\n' && r != '\t' && r != '\r' {
			controlCount++
		}
	}

	return float64(controlCount) / float64(utf8.RuneCountInString(text))
}

func (qa *QAEngine) getAlphaRatio(text string) float64 {
	if len(text) == 0 {
		return 0
	}

	alphaCount := 0
	totalCount := 0

	for _, r := range text {
		if !unicode.IsSpace(r) {
			totalCount++
			if unicode.IsLetter(r) {
				alphaCount++
			}
		}
	}

	if totalCount == 0 {
		return 0
	}

	return float64(alphaCount) / float64(totalCount)
}

func (qa *QAEngine) detectTables(text string) bool {
	lines := strings.Split(text, "\n")
	tableLines := 0

	for _, line := range lines {
		if qa.patterns.tableMarker.MatchString(line) {
			tableLines++
		}
	}

	return float64(tableLines)/float64(len(lines)) > 0.1
}

func (qa *QAEngine) calculateConfidence(report QualityReport) float64 {
	score := 0.0

	if report.WordCount > 50 {
		score += 0.2
	} else if report.WordCount > 10 {
		score += 0.1
	}

	if report.StopwordRatio >= qa.config.MinStopwordRatio {
		score += 0.3
	}

	if report.AlphaRatio >= qa.config.MinAlphaRatio {
		score += 0.2
	}

	if report.ControlCharRatio <= qa.config.MaxControlCharRatio {
		score += 0.1
	}

	if report.RepeatedContentRatio <= qa.config.MaxRepeatThreshold {
		score += 0.2
	}

	return math.Min(1.0, score)
}

func (qa *QAEngine) isTextClean(report QualityReport) bool {
	return report.Confidence >= 0.7 &&
		report.WordCount >= 10 &&
		report.StopwordRatio >= qa.config.MinStopwordRatio &&
		report.AlphaRatio >= qa.config.MinAlphaRatio &&
		report.ControlCharRatio <= qa.config.MaxControlCharRatio
}

// add stopwords for toher languages here
func buildStopwordMap() map[string]bool {
	stopwords := []string{
		"a", "an", "and", "are", "as", "at", "be", "by", "for", "from",
		"has", "he", "in", "is", "it", "its", "of", "on", "that", "the",
		"to", "was", "will", "with", "the", "this", "but", "they", "have",
		"had", "what", "said", "each", "which", "she", "do", "how", "their",
		"if", "will", "up", "other", "about", "out", "many", "then", "them",
		"these", "so", "some", "her", "would", "make", "like", "into", "him",
		"time", "two", "more", "go", "no", "way", "could", "my", "than",
		"first", "been", "call", "who", "oil", "sit", "now", "find", "down",
		"day", "did", "get", "come", "made", "may", "part",
	}

	stopwordMap := make(map[string]bool)
	for _, word := range stopwords {
		stopwordMap[word] = true
	}
	return stopwordMap
}

type PDFProcessor struct {
	qaEngine    *QAEngine
	storagePath string
}

func NewPDFProcessor(storagePath string) *PDFProcessor {
	if err := os.MkdirAll(storagePath, 0755); err != nil {
		panic(fmt.Sprintf("Failed to create storage directory: %v", err))
	}

	return &PDFProcessor{
		qaEngine:    NewQAEngine(DefaultQAConfig()),
		storagePath: storagePath,
	}
}

func (p *PDFProcessor) ProcessPDF(pdfPath string) (string, error) {
	rawText, err := p.extractTextFromPDF(pdfPath)
	if err != nil {
		return "", fmt.Errorf("failed to extract text: %w", err)
	}

	if len(rawText) == 0 {
		return "", fmt.Errorf("no text found in PDF")
	}

	cleanText, report, err := p.qaEngine.ProcessText(rawText)
	if err != nil {
		return "", fmt.Errorf("text quality check failed: %w", err)
	}

	baseFileName := strings.TrimSuffix(filepath.Base(pdfPath), filepath.Ext(pdfPath))
	outputPath := filepath.Join(p.storagePath, baseFileName+".txt")

	if err := p.saveTextWithMetadata(outputPath, cleanText, report); err != nil {
		return "", fmt.Errorf("failed to save processed text: %w", err)
	}

	return outputPath, nil
}

func (p *PDFProcessor) extractTextFromPDF(pdfPath string) (string, error) {
	file, reader, err := pdf.Open(pdfPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var textBuilder strings.Builder
	totalPages := reader.NumPage()

	for pageNum := 1; pageNum <= totalPages; pageNum++ {
		page := reader.Page(pageNum)
		if page.V.IsNull() {
			continue
		}

		texts := page.Content().Text
		for _, text := range texts {
			textBuilder.WriteString(text.S)
			textBuilder.WriteString(" ")
		}
		textBuilder.WriteString("\n")
	}

	return textBuilder.String(), nil
}

func (p *PDFProcessor) saveTextWithMetadata(outputPath string, text string, report QualityReport) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	writer.WriteString("# PDF Processing Metadata\n")
	writer.WriteString(fmt.Sprintf("# Word Count: %d\n", report.WordCount))
	writer.WriteString(fmt.Sprintf("# Line Count: %d\n", report.LineCount))
	writer.WriteString(fmt.Sprintf("# Quality Confidence: %.2f\n", report.Confidence))
	writer.WriteString(fmt.Sprintf("# Stopword Ratio: %.2f\n", report.StopwordRatio))
	writer.WriteString(fmt.Sprintf("# Alpha Ratio: %.2f\n", report.AlphaRatio))
	writer.WriteString(fmt.Sprintf("# Has Tables: %t\n", report.HasTables))
	writer.WriteString("# ===== PROCESSED TEXT =====\n\n")

	writer.WriteString(text)

	return nil
}

type BatchProcessor struct {
	processor   *PDFProcessor
	concurrency int
}

type ProcessResult struct {
	InputPath  string
	OutputPath string
	Error      error
}

func NewBatchProcessor(storagePath string, concurrency int) *BatchProcessor {
	return &BatchProcessor{
		processor:   NewPDFProcessor(storagePath),
		concurrency: concurrency,
	}
}

func (bp *BatchProcessor) ProcessDirectory(dirPath string) ([]string, []error) {
	files, err := filepath.Glob(filepath.Join(dirPath, "*.pdf"))
	if err != nil {
		return nil, []error{err}
	}

	return bp.ProcessFiles(files)
}

func (bp *BatchProcessor) ProcessFiles(files []string) ([]string, []error) {
	if len(files) == 0 {
		return nil, nil
	}

	fileChan := make(chan string, len(files))
	resultChan := make(chan ProcessResult, len(files))

	for i := 0; i < bp.concurrency; i++ {
		go bp.worker(fileChan, resultChan)
	}

	for _, file := range files {
		fileChan <- file
	}
	close(fileChan)

	var outputFiles []string
	var errors []error

	for i := 0; i < len(files); i++ {
		result := <-resultChan
		if result.Error != nil {
			errors = append(errors, result.Error)
		} else {
			outputFiles = append(outputFiles, result.OutputPath)
		}
	}

	return outputFiles, errors
}

func (bp *BatchProcessor) worker(fileChan <-chan string, resultChan chan<- ProcessResult) {
	for filePath := range fileChan {
		outputPath, err := bp.processor.ProcessPDF(filePath)
		resultChan <- ProcessResult{
			InputPath:  filePath,
			OutputPath: outputPath,
			Error:      err,
		}
	}
}

type Statistics struct {
	TotalFiles      int     `json:"total_files"`
	SuccessfulFiles int     `json:"successful_files"`
	FailedFiles     int     `json:"failed_files"`
	SuccessRate     float64 `json:"success_rate"`
	TotalWords      int     `json:"total_words"`
	AvgConfidence   float64 `json:"avg_confidence"`
}

func CalculateStatistics(results []ProcessResult, reports []QualityReport) Statistics {
	stats := Statistics{
		TotalFiles: len(results),
	}

	totalConfidence := 0.0
	totalWords := 0

	for i, result := range results {
		if result.Error == nil {
			stats.SuccessfulFiles++
			if i < len(reports) {
				totalConfidence += reports[i].Confidence
				totalWords += reports[i].WordCount
			}
		} else {
			stats.FailedFiles++
		}
	}

	if stats.TotalFiles > 0 {
		stats.SuccessRate = float64(stats.SuccessfulFiles) / float64(stats.TotalFiles)
	}

	if stats.SuccessfulFiles > 0 {
		stats.AvgConfidence = totalConfidence / float64(stats.SuccessfulFiles)
	}

	stats.TotalWords = totalWords

	return stats
}
