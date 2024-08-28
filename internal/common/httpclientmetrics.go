package common

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type httpClientMetrics struct {
	inFlightGauge prometheus.Gauge
	counter       *prometheus.CounterVec
	duration      *prometheus.HistogramVec
}

var instances = make(map[string]*httpClientMetrics)

//nolint:revive,stylecheck // Easier to read CamelCase
func SetupHttpClientMetrics(name string, transport http.RoundTripper) http.RoundTripper {
	hcm, exists := instances[name]
	if !exists {
		hcm = &httpClientMetrics{}
		instances[name] = hcm

		hcm.counter = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: fmt.Sprintf("%s_requests_total", name),
				Help: fmt.Sprintf("A counter for requests made to %s", name),
			},
			[]string{"method", "code"},
		)
		prometheus.MustRegister(hcm.counter)

		hcm.inFlightGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: fmt.Sprintf("%s_requests_inflight", name),
			Help: fmt.Sprintf("A gauge of requests currently being served by %s", name),
		})
		prometheus.MustRegister(hcm.inFlightGauge)

		// duration is partitioned by the HTTP method and handler. It uses custom
		// buckets based on the expected request duration.
		hcm.duration = prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    fmt.Sprintf("%s_duration_seconds", name),
				Help:    "A histogram of latencies for requests.",
				Buckets: []float64{.1, .5, 1, 2.5, 5, 10},
			},
			[]string{"method", "code"},
		)
		prometheus.MustRegister(hcm.duration)
	}

	return promhttp.InstrumentRoundTripperInFlight(
		hcm.inFlightGauge,
		promhttp.InstrumentRoundTripperCounter(
			hcm.counter,
			promhttp.InstrumentRoundTripperDuration(hcm.duration, transport),
		),
	)
}
