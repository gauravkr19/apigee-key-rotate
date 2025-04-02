package metrics

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Define Prometheus Gauge metrics
var (
	ApigeeKeyTTL = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "apigee_key_ttl_minutes",
			Help: "Time to live (TTL) in minutes for Apigee keys",
		},
		[]string{"app_name"}, // Only app name as a label
	)

	// apigeeKeyCount = prometheus.NewGaugeVec(
	// 	prometheus.GaugeOpts{
	// 		Name: "apigee_key_count",
	// 		Help: "Number of Apigee keys for an app",
	// 	},
	// 	[]string{"app_name"},
	// )
)

// Initialize and register metrics
func InitMetrics() {
	prometheus.MustRegister(ApigeeKeyTTL)
}

// Start the Prometheus metrics server and add a health check endpoint
func StartMetricsServer() {
	http.Handle("/metrics", promhttp.Handler())

	// Add health check endpoint to the same server
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK") // Respond with 200 OK
	})

	// Start the HTTP server (ensure it runs only once)
	go func() {
		if err := http.ListenAndServe(":8080", nil); err != nil {
			fmt.Println("Metrics/Health server failed:", err)
		}
	}()
}
