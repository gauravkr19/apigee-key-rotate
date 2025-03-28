package metrics

import (
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

// Expose Prometheus metrics
func StartMetricsServer() {
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		http.ListenAndServe(":8080", nil) // Change port if needed
	}()
}
