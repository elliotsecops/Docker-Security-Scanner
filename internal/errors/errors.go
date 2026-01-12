package errors

import (
	"fmt"
	"net/http"
	"time"
)

// ErrorType represents different types of errors
type ErrorType string

const (
	ErrorTypeValidation    ErrorType = "validation"
	ErrorTypeConfiguration ErrorType = "configuration"
	ErrorTypeNetwork       ErrorType = "network"
	ErrorTypeDocker        ErrorType = "docker"
	ErrorTypeSecurity      ErrorType = "security"
	ErrorTypeCompliance    ErrorType = "compliance"
	ErrorTypePermission    ErrorType = "permission"
	ErrorTypeTimeout       ErrorType = "timeout"
	ErrorTypeInternal      ErrorType = "internal"
)

// Severity represents error severity levels
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// AppError represents a structured application error
type AppError struct {
	Type        ErrorType                 `json:"type"`
	Severity    Severity                 `json:"severity"`
	Message     string                   `json:"message"`
	Code        string                   `json:"code"`
	Details     map[string]interface{}   `json:"details,omitempty"`
	Timestamp   time.Time                `json:"timestamp"`
	Retryable   bool                     `json:"retryable"`
	HTTPStatus  int                      `json:"http_status"`
	Cause       error                    `json:"-"`
	Stack       string                   `json:"stack,omitempty"`
	Context     map[string]interface{}   `json:"context,omitempty"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Type, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// Unwrap returns the underlying error
func (e *AppError) Unwrap() error {
	return e.Cause
}

// IsRetryable returns whether the error is retryable
func (e *AppError) IsRetryable() bool {
	return e.Retryable
}

// WithDetails adds details to the error
func (e *AppError) WithDetails(details map[string]interface{}) *AppError {
	newError := *e
	newError.Details = details
	return &newError
}

// WithContext adds context to the error
func (e *AppError) WithContext(context map[string]interface{}) *AppError {
	newError := *e
	newError.Context = context
	return &newError
}

// WithCause adds a cause to the error
func (e *AppError) WithCause(cause error) *AppError {
	newError := *e
	newError.Cause = cause
	return &newError
}

// New creates a new application error
func New(errorType ErrorType, message string) *AppError {
	return &AppError{
		Type:       errorType,
		Message:    message,
		Timestamp:  time.Now(),
		Retryable:  false,
		HTTPStatus: http.StatusInternalServerError,
	}
}

// NewValidation creates a new validation error
func NewValidation(message string) *AppError {
	return &AppError{
		Type:       ErrorTypeValidation,
		Severity:   SeverityMedium,
		Message:    message,
		Timestamp:  time.Now(),
		Retryable:  false,
		HTTPStatus: http.StatusBadRequest,
	}
}

// NewConfiguration creates a new configuration error
func NewConfiguration(message string) *AppError {
	return &AppError{
		Type:       ErrorTypeConfiguration,
		Severity:   SeverityHigh,
		Message:    message,
		Timestamp:  time.Now(),
		Retryable:  false,
		HTTPStatus: http.StatusInternalServerError,
	}
}

// NewNetwork creates a new network error
func NewNetwork(message string) *AppError {
	return &AppError{
		Type:       ErrorTypeNetwork,
		Severity:   SeverityMedium,
		Message:    message,
		Timestamp:  time.Now(),
		Retryable:  true,
		HTTPStatus: http.StatusServiceUnavailable,
	}
}

// NewDocker creates a new Docker-specific error
func NewDocker(message string) *AppError {
	return &AppError{
		Type:       ErrorTypeDocker,
		Severity:   SeverityHigh,
		Message:    message,
		Timestamp:  time.Now(),
		Retryable:  true,
		HTTPStatus: http.StatusInternalServerError,
	}
}

// NewSecurity creates a new security error
func NewSecurity(message string) *AppError {
	return &AppError{
		Type:       ErrorTypeSecurity,
		Severity:   SeverityCritical,
		Message:    message,
		Timestamp:  time.Now(),
		Retryable:  false,
		HTTPStatus: http.StatusForbidden,
	}
}

// NewCompliance creates a new compliance error
func NewCompliance(message string) *AppError {
	return &AppError{
		Type:       ErrorTypeCompliance,
		Severity:   SeverityHigh,
		Message:    message,
		Timestamp:  time.Now(),
		Retryable:  false,
		HTTPStatus: http.StatusForbidden,
	}
}

// NewPermission creates a new permission error
func NewPermission(message string) *AppError {
	return &AppError{
		Type:       ErrorTypePermission,
		Severity:   SeverityHigh,
		Message:    message,
		Timestamp:  time.Now(),
		Retryable:  false,
		HTTPStatus: http.StatusForbidden,
	}
}

// NewTimeout creates a new timeout error
func NewTimeout(message string) *AppError {
	return &AppError{
		Type:       ErrorTypeTimeout,
		Severity:   SeverityMedium,
		Message:    message,
		Timestamp:  time.Now(),
		Retryable:  true,
		HTTPStatus: http.StatusRequestTimeout,
	}
}

// NewInternal creates a new internal error
func NewInternal(message string) *AppError {
	return &AppError{
		Type:       ErrorTypeInternal,
		Severity:   SeverityCritical,
		Message:    message,
		Timestamp:  time.Now(),
		Retryable:  false,
		HTTPStatus: http.StatusInternalServerError,
	}
}

// Wrap wraps an existing error with additional context
func Wrap(err error, errorType ErrorType, message string) *AppError {
	if err == nil {
		return nil
	}

	appErr := &AppError{
		Type:       errorType,
		Message:    message,
		Timestamp:  time.Now(),
		Retryable:  false,
		HTTPStatus: http.StatusInternalServerError,
		Cause:      err,
	}

	// Extract severity and retryable status from existing AppError if available
	if existingAppErr, ok := err.(*AppError); ok {
		appErr.Severity = existingAppErr.Severity
		appErr.Retryable = existingAppErr.Retryable
		appErr.HTTPStatus = existingAppErr.HTTPStatus
	}

	return appErr
}

// IsErrorType checks if an error is of a specific type
func IsErrorType(err error, errorType ErrorType) bool {
	if err != nil {
		if appErr, ok := err.(*AppError); ok {
		return appErr.Type == errorType
	}
	return false
	}
	return false
}

// IsRetryable checks if an error is retryable
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}
	if appErr, ok := err.(*AppError); ok {
		return appErr.Retryable
	}
	return false
}

// GetSeverity returns the severity of an error
func GetSeverity(err error) Severity {
	if err == nil {
		return SeverityMedium
	}
	if appErr, ok := err.(*AppError); ok {
		return appErr.Severity
	}
	return SeverityMedium
}

// ErrorCollector collects and manages multiple errors
type ErrorCollector struct {
	errors []*AppError
}

// NewErrorCollector creates a new error collector
func NewErrorCollector() *ErrorCollector {
	return &ErrorCollector{
		errors: make([]*AppError, 0),
	}
}

// Add adds an error to the collector
func (ec *ErrorCollector) Add(err error) {
	if err == nil {
		return
	}

	if appErr, ok := err.(*AppError); ok {
		ec.errors = append(ec.errors, appErr)
	} else {
		ec.errors = append(ec.errors, NewInternal(err.Error()).WithCause(err))
	}
}

// AddError adds an application error to the collector
func (ec *ErrorCollector) AddError(err *AppError) {
	if err != nil {
		ec.errors = append(ec.errors, err)
	}
}

// HasErrors returns true if there are any errors
func (ec *ErrorCollector) HasErrors() bool {
	return len(ec.errors) > 0
}

// HasCriticalErrors returns true if there are any critical errors
func (ec *ErrorCollector) HasCriticalErrors() bool {
	for _, err := range ec.errors {
		if err.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

// GetErrors returns all collected errors
func (ec *ErrorCollector) GetErrors() []*AppError {
	return ec.errors
}

// GetErrorsByType returns errors of a specific type
func (ec *ErrorCollector) GetErrorsByType(errorType ErrorType) []*AppError {
	var result []*AppError
	for _, err := range ec.errors {
		if err.Type == errorType {
			result = append(result, err)
		}
	}
	return result
}

// GetErrorsBySeverity returns errors of a specific severity
func (ec *ErrorCollector) GetErrorsBySeverity(severity Severity) []*AppError {
	var result []*AppError
	for _, err := range ec.errors {
		if err.Severity == severity {
			result = append(result, err)
		}
	}
	return result
}

// Count returns the total number of errors
func (ec *ErrorCollector) Count() int {
	return len(ec.errors)
}

// CountByType returns the number of errors of a specific type
func (ec *ErrorCollector) CountByType(errorType ErrorType) int {
	count := 0
	for _, err := range ec.errors {
		if err.Type == errorType {
			count++
		}
	}
	return count
}

// Clear clears all collected errors
func (ec *ErrorCollector) Clear() {
	ec.errors = make([]*AppError, 0)
}

// Error implements the error interface
func (ec *ErrorCollector) Error() string {
	if len(ec.errors) == 0 {
		return ""
	}
	if len(ec.errors) == 1 {
		return ec.errors[0].Error()
	}
	return fmt.Sprintf("%d errors occurred", len(ec.errors))
}

// ToError returns the collected errors as a single error
func (ec *ErrorCollector) ToError() error {
	if len(ec.errors) == 0 {
		return nil
	}
	if len(ec.errors) == 1 {
		return ec.errors[0]
	}
	return ec
}

// RetryOperation retries an operation with exponential backoff
func RetryOperation(operation func() error, maxAttempts int, initialDelay time.Duration) error {
	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := operation()
		if err == nil {
			return nil
		}

		lastErr = err

		// Check if error is retryable
		if !IsRetryable(err) {
			return err
		}

		// Calculate delay with exponential backoff
		delay := initialDelay * time.Duration(1<<(attempt-1))

		// Wait before retrying
		time.Sleep(delay)
	}

	return lastErr
}