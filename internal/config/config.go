package config

import (
	"os"
	"strconv"
	"strings"
)

const (
	defaultHealthCheckPort = 8000
	defaultMetricsPort     = 8001

	defaultFactoryMaxRequests     = 120
	defaultFactoryRequestInterval = 500

	defaultLogStreamingMethod = "indirect"
	defaultLogFileWrites      = 10000

	defaultSshMaxConnections      = 0    //nolint:revive,stylecheck // Easier to read CamelCase
	defaultSshChannelOpenTimeout  = 30   //nolint:revive,stylecheck // Easier to read CamelCase
	defaultSshChannelCloseTimeout = 5    //nolint:revive,stylecheck // Easier to read CamelCase
	defaultSshOdpPort             = 2022 //nolint:revive,stylecheck // Easier to read CamelCase
	defaultSshOdpConnAttempts     = 3    //nolint:revive,stylecheck // Easier to read CamelCase
	defaultSshOdpConnInterval     = 5    //nolint:revive,stylecheck // Easier to read CamelCase

)

type Config struct {
	LdapURL    string
	LdapCAFile string
	LdapUserDN string

	SsoURL      string
	SsoCAFile   string
	SsoBrokenCA bool

	FactoryURL             string
	FactoryCAFile          string
	FactoryCertFile        string
	FactoryKeyFile         string
	FactoryMaxRequests     int
	FactoryRequestInterval int

	MetricsPort     int
	HealthCheckPort int

	SshHostKeyFile         string //nolint:revive,stylecheck // Easier to read CamelCase
	SshMaxConnections      int    //nolint:revive,stylecheck // Easier to read CamelCase
	SshApplications        string //nolint:revive,stylecheck // Easier to read CamelCase
	SshPorts               string //nolint:revive,stylecheck // Easier to read CamelCase
	SshTokenTypes          string //nolint:revive,stylecheck // Easier to read CamelCase
	SshChannelOpenTimeout  int    //nolint:revive,stylecheck // Easier to read CamelCase
	SshChannelCloseTimeout int    //nolint:revive,stylecheck // Easier to read CamelCase
	SshTokenDataPasswd     string //nolint:revive,stylecheck // Easier to read CamelCase
	SshTokenDataPasswdB64  bool   //nolint:revive,stylecheck // Easier to read CamelCase
	SshOdpPort             int    //nolint:revive,stylecheck // Easier to read CamelCase
	SshOdpConnectAttempts  int    //nolint:revive,stylecheck // Easier to read CamelCase
	SshOdpConnectInterval  int    //nolint:revive,stylecheck // Easier to read CamelCase

	LogControlFile     string
	LogStreamingMethod string
	LogFile            string
	LogFileWrites      int
}

var instance *Config

func GetConfig() *Config {
	if instance == nil {
		instance = &Config{
			LdapURL:    getOsEnvString("LDAP_URL", ""),
			LdapCAFile: getOsEnvString("LDAP_TLS_CA", ""),
			LdapUserDN: getOsEnvString("LDAP_USER_DN", ""),

			SsoURL:      getOsEnvString("SSO_URL", ""),
			SsoCAFile:   getOsEnvString("SSO_CA_FILE", ""),
			SsoBrokenCA: getOsEnvBool("SSO_CA_BROKEN", false),

			FactoryURL:             getOsEnvString("FACTORY_URL", ""),
			FactoryCAFile:          getOsEnvString("FACTORY_CA_FILE", ""),
			FactoryCertFile:        getOsEnvString("FACTORY_CERT_FILE", ""),
			FactoryKeyFile:         getOsEnvString("FACTORY_KEY_FILE", ""),
			FactoryMaxRequests:     getOsEnvInt("FACTORY_MAX_REQUESTS", defaultFactoryMaxRequests),
			FactoryRequestInterval: getOsEnvInt("FACTORY_REQUEST_INTERVAL", defaultFactoryRequestInterval),

			SshHostKeyFile:         getOsEnvString("SSH_HOST_KEY_FILE", ""),
			SshMaxConnections:      getOsEnvInt("SSH_MAX_CONNECTIONS", defaultSshMaxConnections),
			SshApplications:        getOsEnvString("SSH_APPLICATIONS", ""),
			SshPorts:               getOsEnvString("SSH_PORTS", ""),
			SshTokenTypes:          getOsEnvString("SSH_TOKEN_TYPES", ""),
			SshTokenDataPasswd:     getOsEnvString("SSH_TOKEN_DATA_FIELD", ""),
			SshTokenDataPasswdB64:  getOsEnvBool("SSH_TOKEN_DATA_FIELD_B64", false),
			SshOdpPort:             getOsEnvInt("SSH_ODP_PORT", defaultSshOdpPort),
			SshOdpConnectAttempts:  getOsEnvInt("SSH_ODP_CONN_ATTEMPTS", defaultSshOdpConnAttempts),
			SshOdpConnectInterval:  getOsEnvInt("SSH_ODP_CONN_ATTEMPTS", defaultSshOdpConnInterval),
			SshChannelOpenTimeout:  getOsEnvInt("SSH_CHANNEL_OPEN_TIMEOUT", defaultSshChannelOpenTimeout),
			SshChannelCloseTimeout: getOsEnvInt("SSH_CHANNEL_CLOSE_TIMEOUT", defaultSshChannelCloseTimeout),

			// LogControlFile INT.LOG.CTRL for controlling log severity
			LogControlFile:     getOsEnvString("LOG_CTRL_FILE", ""),
			LogFile:            getOsEnvString("LOG_FILE", ""),
			LogFileWrites:      getOsEnvInt("LOG_FILE_WRITES", defaultLogFileWrites),
			LogStreamingMethod: getOsEnvString("LOG_STREAMING_METHOD", defaultLogStreamingMethod),

			HealthCheckPort: getOsEnvInt("HEALTH_CHECK_PORT", defaultHealthCheckPort),
			MetricsPort:     getOsEnvInt("METRICS_PORT", defaultMetricsPort),
		}
	}

	return instance
}

func getOsEnvString(envName string, defaultValue string) string {
	result := strings.TrimSpace(os.Getenv(envName))
	if result == "" {
		result = defaultValue
	}

	return result
}

func getOsEnvInt(envName string, defaultValue int) int {
	envValue := strings.TrimSpace(os.Getenv(envName))

	result, err := strconv.Atoi(envValue)
	if err != nil {
		result = defaultValue
	}

	return result
}

func getOsEnvBool(envName string, defaulValue bool) bool {
	envValue := strings.TrimSpace(os.Getenv(envName))

	value, err := strconv.ParseBool(envValue)
	if err != nil {
		return defaulValue
	}

	return value
}
