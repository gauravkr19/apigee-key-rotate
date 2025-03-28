package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Custom metric for Apigee key rotation
var ApigeeSecretRotate = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "apigee_secret_rotate",
		Help: "Tracks Apigee key rotation per app",
	},
	[]string{"appName", "TTL"},
)

// Initialize and register metrics
func InitMetrics() {
	prometheus.MustRegister(ApigeeSecretRotate)
}

// Expose Prometheus metrics
func StartMetricsServer() {
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		http.ListenAndServe(":8080", nil) // Change port if needed
	}()
}
