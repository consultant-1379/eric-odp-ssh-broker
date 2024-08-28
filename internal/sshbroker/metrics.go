package sshbroker

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	metricsRegistered = false

	metricAccepts        prometheus.Counter
	metricAcceptsRefused *prometheus.CounterVec
	metricChannelOpens   *prometheus.CounterVec
	metricConnections    prometheus.GaugeFunc

	metricTrafficRx prometheus.Counter
	metricTrafficTx prometheus.Counter

	sbRef *SshBrokerImpl
)

func setupMetrics(sb *SshBrokerImpl) {
	sbRef = sb

	if !metricsRegistered {
		metricsRegistered = true

		metricAccepts = prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "sshbroker_accepts_total",
				Help: "A counter for accepted connections",
			},
		)
		prometheus.MustRegister(metricAccepts)

		metricAcceptsRefused = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "sshbroker_accepts_refused_total",
				Help: "A counter for refused connections",
			},
			[]string{"cause"},
		)
		prometheus.MustRegister(metricAcceptsRefused)

		metricChannelOpens = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "sshbroker_channel_opens_total",
				Help: "A counter for ssh channel opens",
			},
			[]string{"type"},
		)
		prometheus.MustRegister(metricChannelOpens)

		metricConnections = prometheus.NewGaugeFunc(
			prometheus.GaugeOpts{
				Name: "sshbroker_connections",
				Help: "Open SSH Connections",
			},
			getConnectionCount,
		)
		prometheus.MustRegister(metricConnections)

		metricTrafficRx = prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "sshbroker_rx_bytes_total",
				Help: "A counter for received from external bytes",
			},
		)
		prometheus.MustRegister(metricTrafficRx)
		metricTrafficTx = prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "sshbroker_tx_bytes_total",
				Help: "A counter for transmitted to external bytes",
			},
		)
		prometheus.MustRegister(metricTrafficTx)
	}
}

func recordAccept() {
	metricAccepts.Inc()
}

func recordAcceptRefused(cause string) {
	metricAcceptsRefused.WithLabelValues(cause).Inc()
}

func recordChannelOpen(chtype string) {
	metricChannelOpens.WithLabelValues(chtype).Inc()
}

func recordTraffic(byteCount int, tx bool) {
	if tx {
		metricTrafficTx.Add(float64(byteCount))
	} else {
		metricTrafficRx.Add(float64(byteCount))
	}
}

func getConnectionCount() float64 {
	return float64(sbRef.openConnections.Load())
}
