package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	vault "github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v3"
)

// VaultClient holds the Vault API client
type VaultClient struct {
	Client            *vault.Client
	expirationTracker map[string]time.Time
}

type Credential struct {
	ConsumerKey    string `json:"consumerKey"`
	ConsumerSecret string `json:"consumerSecret"`
	IssuedAt       int64  `json:"issuedAt"`
	APIProducts    []struct {
		APIProduct string `json:"apiproduct"`
	} `json:"apiProducts"`
}

// Config holds a list of applications.
type Config struct {
	Apps []AppConfig `yaml:"apps"`
}

type AppConfig struct {
	AppName        string `yaml:"app_name"`
	Org            string `yaml:"org"`
	DeveloperEmail string `yaml:"developer_email"`
	VaultPath      string `yaml:"vault_path"`
	VaultMount     string `yaml:"vault_mount"`
	ConsumerKey    string
	IssuedAt       time.Time
	APIProducts    []string
	CustomAttrs    map[string]string
	ExpirationTime time.Time // New field to track expiration time
}

// ApigeeConfig stores centralized settings for Apigee
type ApigeeConfig struct {
	BaseURL       string
	Username      string
	Password      string
	SkipTLSVerify bool
	CAPath        string
	HTTPClient    *http.Client
}

type ApigeeResponse struct {
	Credentials []Credential `json:"credentials"`
	Attributes  []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"attributes"`
}

var apigeeConfig ApigeeConfig // Global Apigee configuration
var ttlDuration time.Duration // Stores TTL duration

// NewVaultClient initializes and returns a Vault API client
func NewVaultClient() (*VaultClient, error) {
	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultRole := os.Getenv("VAULT_ROLE")
	vaultAuthMethod := os.Getenv("VAULT_AUTH_METHOD")
	useTLS := os.Getenv("VAULT_USE_TLS") != "true" // Defaults to false

	config := vault.DefaultConfig()
	config.Address = vaultAddr

	// Configure TLS settings
	if useTLS {
		tlsConfig := vault.TLSConfig{}

		// Check if CA certificate is provided
		caCertPath := os.Getenv("VAULT_CACERT")
		if caCertPath != "" {
			// Load CA certificate
			caCert, err := os.ReadFile(caCertPath)
			if err != nil {
				log.Println("Failed to read CA certificate:", err)
			}

			// Create a certificate pool and append the CA certificate
			caCertPool := x509.NewCertPool()
			if caCertPool.AppendCertsFromPEM(caCert) {
				tlsConfig.CACert = caCertPath
				log.Println("CA certificate loaded from", caCertPath)
			} else {
				log.Println("Failed to append CA certificate to pool")
			}
		} else {
			// If no CA certificate is provided, use InsecureSkipVerify
			tlsConfig.Insecure = true
			log.Println("No CA certificate provided. Using InsecureSkipVerify=true for TLS.")
		}

		// Apply TLS settings
		if err := config.ConfigureTLS(&tlsConfig); err != nil {
			return nil, fmt.Errorf("TLS configuration error: %v", err)
		}
	} else {
		log.Println("TLS is disabled. Connecting to Vault without encryption.")
	}

	// Initialize Vault client
	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("Failed to create Vault client: %v", err)
	}

	// Read Kubernetes JWT Token
	jwtToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, fmt.Errorf("Failed to read service account JWT token: %v", err)
	}

	// Authenticate with Vault using Kubernetes Auth
	authPayload := map[string]interface{}{
		"jwt":  string(jwtToken),
		"role": vaultRole,
	}

	authPath := fmt.Sprintf("auth/%s/login", vaultAuthMethod)
	secret, err := client.Logical().Write(authPath, authPayload)
	if err != nil {
		return nil, fmt.Errorf("Vault authentication failed: %v", err)
	}

	// Set Vault token
	client.SetToken(secret.Auth.ClientToken)
	log.Println("Successfully authenticated with Vault")

	return &VaultClient{Client: client}, nil
}

// initializeApigeeConfig sets up the Apigee configuration and HTTP client
func initializeApigeeConfig() error {
	apigeeConfig = ApigeeConfig{
		BaseURL:       os.Getenv("APIGEE_URL"),
		Username:      os.Getenv("APIGEE_USERNAME"),
		Password:      os.Getenv("APIGEE_PASSWORD"),
		SkipTLSVerify: os.Getenv("APIGEE_SKIP_TLS_VERIFY") == "true",
		CAPath:        os.Getenv("APIGEE_CA_PATH"),
	}

	// Set up HTTP client with custom TLS settings
	tlsConfig := &tls.Config{
		InsecureSkipVerify: apigeeConfig.SkipTLSVerify, // Skip verification for self-signed certs
	}

	// Load custom CA if provided
	if apigeeConfig.CAPath != "" {
		caCert, err := os.ReadFile(apigeeConfig.CAPath)
		if err != nil {
			return fmt.Errorf("failed to read CA file: %v", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return fmt.Errorf("failed to append CA certificate")
		}
		tlsConfig.RootCAs = caPool
	}

	apigeeConfig.HTTPClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	log.Println("Apigee configuration initialized successfully")
	return nil
}

// newApigeeRequest creates a new HTTP request with authentication
func (app *AppConfig) newApigeeRequest(method, endpoint string, body io.Reader) (*http.Request, *http.Client, error) {
	url := fmt.Sprintf("%s/%s", apigeeConfig.BaseURL, endpoint)
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.SetBasicAuth(apigeeConfig.Username, apigeeConfig.Password)
	req.Header.Set("Content-Type", "application/json")

	return req, apigeeConfig.HTTPClient, nil
}

// rotateApigeeKeys retrieves the keys, products, creates keys, associate with products and delete old key
func (app *AppConfig) rotateApigeeKeys(vc *VaultClient) error {
	req, client, err := app.newApigeeRequest("GET", fmt.Sprintf("v1/organizations/%s/developers/%s/apps/%s", app.Org, app.DeveloperEmail, app.AppName), nil)

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var apiResp ApigeeResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil
	}

	// Initialize custom attributes map for this app
	app.CustomAttrs = make(map[string]string)
	for _, attr := range apiResp.Attributes {
		app.CustomAttrs[attr.Name] = attr.Value
	}

	// Check if there are any credentials
	if len(apiResp.Credentials) == 0 {
		return fmt.Errorf("no credentials found for app %s", app.AppName)
	}

	// Sort credentials by IssuedAt (most recent first)
	sort.Slice(apiResp.Credentials, func(i, j int) bool {
		return apiResp.Credentials[i].IssuedAt > apiResp.Credentials[j].IssuedAt
	})

	// Select the latest key
	latestCredential := apiResp.Credentials[0]
	app.ConsumerKey = latestCredential.ConsumerKey
	app.IssuedAt = time.UnixMilli(latestCredential.IssuedAt)

	// Extract API Products
	app.APIProducts = nil // Clear any previous values before appending
	for _, product := range latestCredential.APIProducts {
		app.APIProducts = append(app.APIProducts, product.APIProduct)
	}

	// Print extracted values
	log.Println("--- Extracted Details before key rotation ---")
	log.Println("App Name:", app.AppName)

	var wg sync.WaitGroup
	if len(apiResp.Credentials) == 1 {
		// Generate secret text to use as key, secret
		newKey, newSecret, err := generateCredentials()
		// Rotate key by creating new app Key + associate products
		err = app.createApigeeKey(newKey, newSecret)
		if err != nil {
			return fmt.Errorf("Failed to create new key for %s: %v", app.AppName, err)
		}
		log.Printf("New key added to %s app successfully \n", app.AppName)

		// renew expiration time and update tracker and Vault
		ttlStr := os.Getenv("TTL")
		ttlDuration, err := parseTTL(ttlStr)
		if err != nil {
			log.Fatalf("Invalid TTL format: %v", err)
		}
		expTime := time.Now().Add(ttlDuration)
		vc.expirationTracker[app.AppName] = expTime

		// Write to Vault before deleting old key
		err = vc.WriteToVault(*app, newKey, newSecret, expTime)
		if err != nil {
			return fmt.Errorf("Failed to write secrets to Vault for %s: %v", app.AppName, err)
		}

		// Invoke deletion of old key
		wg.Add(1)
		go func() {
			defer wg.Done()
			err = app.deleteOldApigeeKey()
			if err != nil {
				log.Printf("Failed to delete old key for %s: %v\n", app.AppName, err)
			}
		}()
	}
	wg.Wait() // Wait for the deletion to complete before returning

	if len(apiResp.Credentials) != 1 {
		log.Printf("Skipping the rotation, keys count is not equal to one for %s: \n", app.AppName)
	}
	return nil
}

// fetchApigeeKeys retrieves the keys, products to validate
func (app *AppConfig) fetchApigeeKeys() ([]Credential, error) {
	req, client, err := app.newApigeeRequest("GET", fmt.Sprintf("v1/organizations/%s/developers/%s/apps/%s", app.Org, app.DeveloperEmail, app.AppName), nil)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var apiResp ApigeeResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, err
	}

	// Initialize custom attributes map for this app
	app.CustomAttrs = make(map[string]string)
	for _, attr := range apiResp.Attributes {
		app.CustomAttrs[attr.Name] = attr.Value
	}

	// Check if there are any credentials
	if len(apiResp.Credentials) == 0 {
		return nil, fmt.Errorf("no credentials found for app %s", app.AppName)
	}

	// Sort credentials by IssuedAt (most recent first)
	sort.Slice(apiResp.Credentials, func(i, j int) bool {
		return apiResp.Credentials[i].IssuedAt > apiResp.Credentials[j].IssuedAt
	})

	// Select the latest key
	latestCredential := apiResp.Credentials[0]
	app.ConsumerKey = latestCredential.ConsumerKey
	app.IssuedAt = time.UnixMilli(latestCredential.IssuedAt)

	// Extract API Products
	app.APIProducts = nil // Clear any previous values before appending
	for _, product := range latestCredential.APIProducts {
		app.APIProducts = append(app.APIProducts, product.APIProduct)
	}

	// Print extracted values
	log.Println("--- Extracted Details ---")
	log.Println("App Name:", app.AppName)

	return apiResp.Credentials, nil
}

// createApigeeKey first creates a key, then associates API products.
func (app *AppConfig) createApigeeKey(key, secret string) error {
	// Step 1: Create the Key
	createPayload := map[string]string{
		"consumerKey":    key,
		"consumerSecret": secret,
	}

	createPayloadBytes, err := json.Marshal(createPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal create payload: %v", err)
	}

	// Use newApigeeRequest to create the key
	req, client, err := app.newApigeeRequest("POST", fmt.Sprintf("v1/organizations/%s/developers/%s/apps/%s/keys/create", app.Org, app.DeveloperEmail, app.AppName), bytes.NewBuffer(createPayloadBytes))
	if err != nil {
		return fmt.Errorf("key creation failed for %s: %v", app.AppName, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create key: received status %d", resp.StatusCode)
	}
	log.Println("Key successfully created for:", app.AppName)

	associatePayload := map[string][]string{
		"apiProducts": app.APIProducts,
	}
	associatePayloadBytes, err := json.Marshal(associatePayload)
	if err != nil {
		return fmt.Errorf("failed to marshal associate payload: %v", err)
	}

	// Step 2: Associate the Key with API Products
	req, client, err = app.newApigeeRequest("POST", fmt.Sprintf("v1/organizations/%s/developers/%s/apps/%s/keys/%s", app.Org, app.DeveloperEmail, app.AppName, key), bytes.NewBuffer(associatePayloadBytes))
	if err != nil {
		return fmt.Errorf("Associating products to %s App failed: %v", app.AppName, err)
	}

	resp, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed for associating API products: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to associate API products: received status %d", resp.StatusCode)
	}

	log.Println("API Products successfully associated for:", app.AppName)
	return nil
}

// deleteOldApigeeKey deletes the oldest key if exactly 2 keys exist
func (app *AppConfig) deleteOldApigeeKey() error {
	// Step 1: Fetch the existing keys
	credentials, err := app.fetchApigeeKeys()
	if err != nil {
		return fmt.Errorf("error fetching credentials for %s: %v", app.AppName, err)
	}

	// Step 2: Apply deletion logic (delete only if exactly 2 keys exist)
	if len(credentials) != 2 {
		return fmt.Errorf("Skipping deletion as key count is %d for app %s: %v ", len(credentials), app.AppName, err)
	}

	// Step 3: Find the oldest key
	oldestKey := credentials[0].ConsumerKey
	oldestIssuedAt := credentials[0].IssuedAt
	for _, cred := range credentials[1:] {
		if cred.IssuedAt < oldestIssuedAt {
			oldestKey = cred.ConsumerKey
			oldestIssuedAt = cred.IssuedAt
		}
	}

	// Step 4: Get delay duration (e.g., "5m", "7d", "3h", "2mo") from env var to delete old key, secret
	keyDeletionDelayStr := os.Getenv("KEY_DELETION_DELAY")
	keyDeletionDelay, err := parseTTL(keyDeletionDelayStr)

	fmt.Println("keyDeletionDelay Duration", keyDeletionDelay)
	if err != nil {
		log.Printf("Invalid KEY_DELETION_DELAY: %v. Using default 6h.", err)
		keyDeletionDelay = 6 * time.Hour // Fallback to default
	}

	log.Printf("Scheduling deletion of old key in %s for app: %s\n", keyDeletionDelay, app.AppName)

	time.AfterFunc(keyDeletionDelay, func() {
		log.Printf("Deleting old key for app: %s now...", app.AppName)

		deleteURL := fmt.Sprintf("v1/organizations/%s/developers/%s/apps/%s/keys/%s",
			app.Org, app.DeveloperEmail, app.AppName, oldestKey)

		req, client, err := app.newApigeeRequest("DELETE", deleteURL, nil)
		if err != nil {
			log.Printf("Failed to create delete request for %s: %v", app.AppName, err)
			return
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Request failed for %s: %v", app.AppName, err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
			log.Printf("Failed to delete key for %s: received status %d", app.AppName, resp.StatusCode)
			return
		}

		log.Printf("Successfully deleted oldest key for %s\n", app.AppName)
	})

	return nil
}

// generateSecureKey generates a secure key of the given length using a mix of uppercase, lowercase, and digits.
func generateSecureKey(length int) (string, error) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	bytes := make([]byte, length)
	charsetLength := len(charset)

	for i := range bytes {
		randomByte := make([]byte, 1)
		_, err := rand.Read(randomByte) // Read 1 random byte
		if err != nil {
			return "", fmt.Errorf("failed to generate random byte: %v", err)
		}
		bytes[i] = charset[randomByte[0]%byte(charsetLength)] // Map random byte to charset
	}
	return string(bytes), nil
}

// generateCredentials generates a secure consumer key and secret.
func generateCredentials() (string, string, error) {
	consumerKey, err := generateSecureKey(32) // 32-char secure key
	if err != nil {
		return "", "", err
	}
	consumerSecret, err := generateSecureKey(16) // 64-char secure secret
	if err != nil {
		return "", "", err
	}
	return consumerKey, consumerSecret, nil
}

// ReadConfig reads the config.yaml file and unmarshals it into Config struct.
func ReadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// parseTTL converts TTL string (e.g., "5m", "7d") into a time.Duration.
// func parseTTL(ttlStr string) (time.Duration, error) {
// 	if strings.HasSuffix(ttlStr, "m") { // Minutes
// 		minutes, err := strconv.Atoi(strings.TrimSuffix(ttlStr, "m"))
// 		if err != nil {
// 			return 0, fmt.Errorf("invalid TTL format: %s", ttlStr)
// 		}
// 		return time.Duration(minutes) * time.Minute, nil
// 	} else if strings.HasSuffix(ttlStr, "d") { // Days
// 		days, err := strconv.Atoi(strings.TrimSuffix(ttlStr, "d"))
// 		if err != nil {
// 			return 0, fmt.Errorf("invalid TTL format: %s", ttlStr)
// 		}
// 		return time.Duration(days*24) * time.Hour, nil
// 	}
// 	return 0, fmt.Errorf("unsupported TTL format: %s", ttlStr)
// }

// parseTTL converts TTL/KEY_DELETION_DELAY string (e.g., "5m", "7d", "3h", "2mo") into a time.Duration.
func parseTTL(ttlStr string) (time.Duration, error) {
	// Define regex to match TTL formats: minutes (m), hours (h), days (d), months (mo)
	re := regexp.MustCompile(`^(\d+)(m|h|d|mo)$`)
	matches := re.FindStringSubmatch(ttlStr)

	if len(matches) != 3 {
		return 0, fmt.Errorf("unsupported TTL format: %s", ttlStr)
	}

	value, err := strconv.Atoi(matches[1]) // Extract the numeric value
	if err != nil {
		return 0, fmt.Errorf("invalid TTL value: %s", ttlStr)
	}

	unit := matches[2]
	switch unit {
	case "m": // Minutes
		return time.Duration(value) * time.Minute, nil
	case "h": // Hours
		return time.Duration(value) * time.Hour, nil
	case "d": // Days
		return time.Duration(value*24) * time.Hour, nil
	case "mo": // Months (approximated as 30 days)
		return time.Duration(value*30*24) * time.Hour, nil
	default:
		return 0, fmt.Errorf("unsupported TTL unit: %s", ttlStr)
	}
}

func (vc *VaultClient) expirationWatcher(config *Config) {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		for i := range config.Apps {
			app := &config.Apps[i] // Pointer to modify if needed
			expTime, exists := vc.expirationTracker[app.AppName]
			if !exists {
				log.Printf("App %s not found in expirationTracker, validate the config", app.AppName)
				vc.ValidateConfig(config)
			}

			ttlMinutes := int64(expTime.Sub(now).Minutes()) // Convert TTL to minutes

			// Fetch Key Count
			credentials, err := app.fetchApigeeKeys()
			if err != nil {
				log.Printf("❌ Failed to fetch keys for %s: %v", app.AppName, err)
				continue
			}
			keyCount := len(credentials)

			// Update Prometheus metrics
			apigeeSecretRotate.WithLabelValues(app.AppName, fmt.Sprintf("%d", ttlMinutes), fmt.Sprintf("%d", keyCount)).Set(float64(keyCount))

			// Check if key rotation is needed
			if now.After(expTime) {
				log.Printf("🚨 TTL expired for %s, triggering key rotation...", app.AppName)

				err := app.rotateApigeeKeys(vc)
				if err != nil {
					log.Printf("❌ Failed to rotate key for %s: %v", app.AppName, err)
					continue
				}

				delete(vc.expirationTracker, app.AppName) // Remove expired entry
			}
		}
	}
}

// // concurrent read via goroutine
func (vc *VaultClient) batchReadVaultData(apps []AppConfig) map[string]map[string]interface{} {
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make(map[string]map[string]interface{})

	for _, app := range apps {
		wg.Add(1)

		go func(app AppConfig) {
			defer wg.Done()

			vaultData, err := vc.readVaultData(app)
			if err != nil {
				log.Printf("Failed to read Vault for %s: %v\n", app.AppName, err)
				return
			}

			mu.Lock()
			results[app.AppName] = vaultData
			mu.Unlock()
		}(app)
	}

	wg.Wait()
	return results
}

// New
func (vc *VaultClient) readVaultData(app AppConfig) (map[string]interface{}, error) {
	vaultPath := fmt.Sprintf("%s/data/%s", app.VaultMount, app.VaultPath)
	secret, err := vc.Client.Logical().Read(vaultPath)
	if err != nil {
		return nil, fmt.Errorf("Vault read failed: %v", err)
	}

	if secret == nil || secret.Data["data"] == nil {
		return nil, fmt.Errorf("No data found for path: %s", vaultPath)
	}

	data := secret.Data["data"].(map[string]interface{})
	return map[string]interface{}{
		"app":            data["app"],
		"key":            data["key"],
		"secret":         data["secret"],
		"expirationTime": data["expirationTime"],
	}, nil
}

// New
func (vc *VaultClient) WriteToVault(app AppConfig, key, secret string, expirationTime time.Time) error {
	vaultPath := fmt.Sprintf("%s/data/%s", app.VaultMount, app.VaultPath)
	data := map[string]interface{}{
		"data": map[string]interface{}{
			"app":            app.AppName,
			"key":            key,
			"secret":         secret,
			"expirationTime": expirationTime.Format(time.RFC3339),
		},
	}

	_, err := vc.Client.Logical().Write(vaultPath, data)
	if err != nil {
		return fmt.Errorf("Failed to write to Vault: %v", err)
	}

	log.Printf("Successfully written secrets to Vault at %s", vaultPath)
	return nil
}

// New
func (vc *VaultClient) patchVaultExpiration(app *AppConfig, newExpiration time.Time) error {
	// Ensure Vault client is available
	if vc.Client == nil {
		return fmt.Errorf("Vault client is not initialized")
	}

	// Construct Vault path
	vaultPath := fmt.Sprintf("%s/data/%s", app.VaultMount, app.VaultPath)

	// Read the existing data from Vault
	secret, err := vc.Client.Logical().Read(vaultPath)
	if err != nil {
		return fmt.Errorf("Failed to read Vault data for %s: %v", app.AppName, err)
	}

	if secret == nil || secret.Data == nil {
		return fmt.Errorf("No existing data found in Vault for %s", app.AppName)
	}

	// Extract current secret data
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("Vault response format invalid for %s", app.AppName)
	}

	// Update only the expirationTime field
	data["expirationTime"] = newExpiration.Format(time.RFC3339)

	// Write updated data back to Vault
	_, err = vc.Client.Logical().Write(vaultPath, map[string]interface{}{"data": data})
	if err != nil {
		return fmt.Errorf("Failed to update expirationTime in Vault for %s: %v", app.AppName, err)
	}

	// Update in-memory expiration tracker
	vc.expirationTracker[app.AppName] = newExpiration

	// Optionally, update the struct field for consistency
	app.ExpirationTime = newExpiration

	log.Printf("Successfully updated expirationTime for %s in Vault\n", app.AppName)
	return nil
}

// New
func (vc *VaultClient) ValidateConfig(config *Config) {
	ttlStr := os.Getenv("TTL")
	ttlDuration, err := parseTTL(ttlStr)
	fmt.Println("TTL:", ttlDuration)
	if err != nil {
		log.Fatalf("Invalid TTL format: %v", err)
	}

	// Ensure expirationTracker is initialized
	if vc.expirationTracker == nil {
		vc.expirationTracker = make(map[string]time.Time)
	}

	// Parallel batch read from Vault
	vaultResults := vc.batchReadVaultData(config.Apps)

	for _, app := range config.Apps {

		// Reset values at the start of each iteration
		var expirationTimeStr string
		var existsExpiration bool = false // Explicit reset

		appData, existsInVault := vaultResults[app.AppName]
		if err != nil {
			log.Printf("Vault read failed for %s: %v\n", app.AppName, err)
			continue
		}

		// Handle possible expirationTime types
		if rawExp, ok := appData["expirationTime"]; ok {
			switch v := rawExp.(type) {
			case string:
				expirationTimeStr, existsExpiration = v, true
			case float64:
				expirationTimeStr, existsExpiration = strconv.FormatFloat(v, 'f', -1, 64), true
			case json.Number:
				expirationTimeStr, existsExpiration = v.String(), true
			default:
				log.Printf(" Unknown type for expirationTime: %T\n", v)
			}
		}

		_, existsKey := appData["key"].(string)
		_, existsSecret := appData["secret"].(string)
		_, existsApp := appData["app"].(string)

		// Case i) Vault's expirationTime is in the past → Reset and PATCH Vault
		if existsExpiration {
			expirationTime, err := time.Parse(time.RFC3339, expirationTimeStr)
			if err != nil {
				log.Printf("Failed to parse expirationTime for %s: %v", app.AppName, err)
				continue
			}
			if expirationTime.Before(time.Now()) {
				log.Printf("Vault's expirationTime field is invalid for %s. Resetting expiration time...\n", app.AppName)
				newExpiration := time.Now().Add(ttlDuration)
				vc.expirationTracker[app.AppName] = newExpiration

				// PATCH only expirationTime in Vault
				err := vc.patchVaultExpiration(&app, newExpiration)
				if err != nil {
					log.Printf("Failed to patch expiration for %s: %v", app.AppName, err)
				}
				continue
			}
		}

		// Case ii) All keys missing → Fetch from Apigee, write to Vault
		if !existsInVault {
			log.Printf("No Vault entry found for %s. Fetching keys from Apigee...\n", app.AppName)

			creds, err := app.fetchApigeeKeys()
			if err != nil {
				log.Printf("Failed to fetch keys for %s: %v", app.AppName, err)
				continue
			}

			expTime := time.Now().Add(ttlDuration) // Set expiration using TTL
			vc.expirationTracker[app.AppName] = expTime

			// Write key & expiration to Vault
			err = vc.WriteToVault(app, creds[0].ConsumerKey, creds[0].ConsumerSecret, expTime)
			if err != nil {
				log.Printf("Failed to write to Vault for %s: %v", app.AppName, err)
			}
			continue
		}

		// Case iii) Vault entry exists, but missing in expirationTracker -> Refresh map
		if existsInVault && !vc.hasExpirationTrackerEntry(app.AppName) {
			log.Printf(" Vault entry exists for %s, but missing from expirationTracker. Refreshing...\n", app.AppName)
			expTime, _ := time.Parse(time.RFC3339, expirationTimeStr)
			vc.expirationTracker[app.AppName] = expTime
			continue
		}

		// Vault entry is missing, but expirationTracker entry exists - unlikely
		if !existsInVault && vc.hasExpirationTrackerEntry(app.AppName) {
			log.Printf("Stale entry: expirationTracker contains %s, but Vault entry is missing. Skipping...\n", app.AppName)
			continue
		}

		// **Case iv: Check for multiple credentials even if keys exist in Vault**
		// creds, err := app.fetchApigeeKeys()
		// if err != nil {
		// 	log.Printf("Failed to fetch Apigee keys for %s: %v", app.AppName, err)
		// 	continue
		// }

		// if len(creds) > 1 {
		// 	log.Printf("Warning: Multiple credentials returned for %s. Using the first one.", app.AppName)
		// }

		// Case iv)  All 4 fields exist, ideal case -> Track expiration
		if existsInVault && existsKey && existsSecret && existsApp && existsExpiration {
			expirationTime, err := time.Parse(time.RFC3339, expirationTimeStr)

			rawExpTime, existsExpiration := appData["expirationTime"]
			log.Printf("Raw expirationTime value for %s: %#v (Exists: %v)\n", app.AppName, rawExpTime, existsExpiration)

			if err != nil {
				log.Printf("Invalid expirationTime format in Vault for %s", app.AppName)
				continue
			}

			// Track expiration
			vc.expirationTracker[app.AppName] = expirationTime
			continue
		}
	}
	log.Printf("Validation complete, tracking the TTLs until key expiration for each of the apps")

	// Start expiration watcher only if there are valid tracked entries
	if len(vc.expirationTracker) > 0 {
		go vc.expirationWatcher(config)
	}
}

func (vc *VaultClient) hasExpirationTrackerEntry(appName string) bool {
	_, exists := vc.expirationTracker[appName]
	return exists
}

func main() {
	// Initialize Prometheus metrics
	initMetrics()

	// Start HTTP server for Prometheus metrics
	startMetricsServer()

	// Initialize Apigee config and HTTP client
	if err := initializeApigeeConfig(); err != nil {
		log.Println("Failed to initialize Apigee:", err)
		return
	}

	// Read config.yaml
	config, err := ReadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// Initialize Vault client
	vaultClient, err := NewVaultClient()
	if err != nil {
		log.Fatalf("Failed to initialize Vault client: %v", err)
	}

	// Validate config and set up expiration tracking
	vaultClient.ValidateConfig(config)

	// Block the main thread (needed for Kubernetes pod)
	select {}
}
