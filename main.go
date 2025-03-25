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
	"sort"
	"strconv"
	"strings"
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
// var expirationTracker = make(map[string]time.Time) // Tracks expiration times per app
var ttlDuration time.Duration // Stores TTL duration

// NewVaultClient initializes and returns a Vault API client
func NewVaultClient() (*VaultClient, error) {
	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultRole := os.Getenv("VAULT_ROLE")
	vaultAuthPath := os.Getenv("VAULT_AUTH_PATH")
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
				log.Println("❌ Failed to read CA certificate:", err)
			}

			// Create a certificate pool and append the CA certificate
			caCertPool := x509.NewCertPool()
			if caCertPool.AppendCertsFromPEM(caCert) {
				tlsConfig.CACert = caCertPath
				log.Println("✅ CA certificate loaded from", caCertPath)
			} else {
				log.Println("❌ Failed to append CA certificate to pool")
			}
		} else {
			// If no CA certificate is provided, use InsecureSkipVerify
			tlsConfig.Insecure = true
			log.Println("⚠ No CA certificate provided. Using InsecureSkipVerify=true for TLS.")
		}

		// Apply TLS settings
		if err := config.ConfigureTLS(&tlsConfig); err != nil {
			return nil, fmt.Errorf("❌ TLS configuration error: %v", err)
		}
	} else {
		log.Println("⚠ TLS is disabled. Connecting to Vault without encryption.")
	}

	// Initialize Vault client
	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("❌ Failed to create Vault client: %v", err)
	}

	// Read Kubernetes JWT Token
	jwtToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, fmt.Errorf("❌ Failed to read service account JWT token: %v", err)
	}

	// Authenticate with Vault using Kubernetes Auth
	authPayload := map[string]interface{}{
		"jwt":  string(jwtToken),
		"role": vaultRole,
	}

	authPath := fmt.Sprintf("auth/%s/login", vaultAuthPath)
	secret, err := client.Logical().Write(authPath, authPayload)
	if err != nil {
		return nil, fmt.Errorf("❌ Vault authentication failed: %v", err)
	}

	// Set Vault token
	client.SetToken(secret.Auth.ClientToken)
	log.Println("✅ Successfully authenticated with Vault")

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

	fmt.Println("✅ Apigee configuration initialized successfully")
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

// fetchApigeeKeys retrieves the keys, products
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
	fmt.Println("--- Extracted Details ---")
	fmt.Println("App Name:", app.AppName)
	fmt.Println("API Products:", app.APIProducts)
	fmt.Println("This will go to Vault at:", app.VaultPath)
	fmt.Println()

	var wg sync.WaitGroup
	if len(apiResp.Credentials) == 1 {
		// Generate secret text to use as key, secret
		newKey, newSecret, err := generateCredentials()
		// Rotate key by creating new app Key + associate products
		err = app.createApigeeKey(newKey, newSecret)
		if err != nil {
			return nil, fmt.Errorf("❌ Failed to create new key for %s: %v", app.AppName, err)
		}
		fmt.Printf("✅ New key added to %s app successfully \n", app.AppName)

		// Fetch expiration time from tracker
		expirationTime, exists := expirationTracker[app.AppName]
		if !exists {
			expirationTime = time.Now().Add(ttlDuration) // Default if not found
		}
		// Write to Vault before deleting old key
		// err = app.writeToVault(newKey, newSecret, expirationTime)
		err = vc.WriteToVault(*app, newKey, newSecret, &expirationTime)

		if err != nil {
			return nil, fmt.Errorf("❌ Failed to write secrets to Vault for %s: %v", app.AppName, err)
		}
		fmt.Printf("🔑 Successfully written new credentials to Vault for %s\n", app.AppName)

		// Invoke deletion of old key
		wg.Add(1)
		go func() {
			defer wg.Done()
			err = app.deleteOldApigeeKey()
			if err != nil {
				fmt.Printf("❌ Failed to delete old key for %s: %v\n", app.AppName, err)
			}
		}()
	}
	// Wait for the deletion to complete before returning
	wg.Wait()
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
	fmt.Println("✅ Key successfully created for:", app.AppName)

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

	fmt.Println("✅ API Products successfully associated for:", app.AppName)
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

	// Step 4: Wait 6 hours before deletion
	fmt.Printf("🕒 Scheduling deletion of old key in 6 hours for app: %s\n", app.AppName)
	time.Sleep(2 * time.Second)

	// Step 5: Delete the oldest key
	deleteURL := fmt.Sprintf("v1/organizations/%s/developers/%s/apps/%s/keys/%s", app.Org, app.DeveloperEmail, app.AppName, oldestKey)
	req, client, err := app.newApigeeRequest("DELETE", deleteURL, nil)
	if err != nil {
		return fmt.Errorf("failed to delete the key for app %s: %v ", app.AppName, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %v for %s", err, app.AppName)
	}
	defer resp.Body.Close()

	// Return error with HTTP status code for all except 200 and 204
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to delete key for %s: received status %d", app.AppName, resp.StatusCode)
	}

	fmt.Printf("✅ Successfully deleted oldest key for %s\n", app.AppName)
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
func parseTTL(ttlStr string) (time.Duration, error) {
	if strings.HasSuffix(ttlStr, "m") { // Minutes
		minutes, err := strconv.Atoi(strings.TrimSuffix(ttlStr, "m"))
		if err != nil {
			return 0, fmt.Errorf("invalid TTL format: %s", ttlStr)
		}
		return time.Duration(minutes) * time.Minute, nil
	} else if strings.HasSuffix(ttlStr, "d") { // Days
		days, err := strconv.Atoi(strings.TrimSuffix(ttlStr, "d"))
		if err != nil {
			return 0, fmt.Errorf("invalid TTL format: %s", ttlStr)
		}
		return time.Duration(days*24) * time.Hour, nil
	}
	return 0, fmt.Errorf("unsupported TTL format: %s", ttlStr)
}

func (vc *VaultClient) expirationWatcher(config *Config) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		for appName, expTime := range vc.expirationTracker {
			if now.After(expTime) {
				log.Printf("🔄 TTL expired for %s, triggering key rotation...", appName)

				for i := range config.Apps {
					if config.Apps[i].AppName == appName {
						_, err := config.Apps[i].fetchApigeeKeys()
						if err != nil {
							log.Printf("❌ Failed to rotate key for %s: %v", appName, err)
							continue
						}
						break
					}
				}
			}
		}
	}
}

// New
func (vc *VaultClient) readVaultData(app AppConfig) (map[string]interface{}, error) {
	vaultPath := fmt.Sprintf("%s/data/%s", app.VaultMount, app.VaultPath)
	secret, err := vc.Client.Logical().Read(vaultPath)
	if err != nil {
		return nil, fmt.Errorf("❌ Vault read failed: %v", err)
	}

	if secret == nil || secret.Data["data"] == nil {
		return nil, fmt.Errorf("❌ No data found for path: %s", vaultPath)
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
func (vc *VaultClient) writeToVault(app AppConfig, key, secret string, expirationTime time.Time) error {
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
		return fmt.Errorf("❌ Failed to write to Vault: %v", err)
	}

	log.Printf("🔑 Successfully written secrets to Vault at %s", vaultPath)
	return nil
}

// New
func (vc *VaultClient) patchVaultExpiration(app *AppConfig, newExpiration time.Time) error {
	// Ensure Vault client is available
	if vc.Client == nil {
		return fmt.Errorf("❌ Vault client is not initialized")
	}

	vaultAddr := vc.Client.Address()
	token := vc.Client.Token()

	// Construct Vault KV-2 API endpoint
	url := fmt.Sprintf("%s/v1/%s/data/%s", vaultAddr, app.VaultMount, app.VaultPath)

	// Prepare the payload for patching expiration_time
	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"expiration_time": app.ExpirationTime.Format(time.RFC3339),
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("❌ Failed to marshal patch payload: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("PATCH", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("❌ Failed to create patch request: %w", err)
	}

	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")

	// Send request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("❌ Failed to patch Vault expiration: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("❌ Vault patch failed, status: %d, response: %s", resp.StatusCode, string(body))
	}

	log.Printf("✅ Successfully patched expiration_time for app %s in Vault", app.AppName)
	return nil
}

// New
func (vc *VaultClient) ValidateConfig(config *Config) {
	ttlStr := os.Getenv("TTL")
	ttlDuration, err := parseTTL(ttlStr)
	if err != nil {
		log.Fatalf("❌ Invalid TTL format: %v", err)
	}

	// Ensure expirationTracker is initialized
	if vc.expirationTracker == nil {
		vc.expirationTracker = make(map[string]time.Time)
	}

	// Parallel batch read from Vault
	vaultResults := vc.batchReadVaultData(config.Apps)

	for _, app := range config.Apps {
		appData, existsInVault := vaultResults[app.AppName]
		expirationTimeStr, existsExpiration := appData["expirationTime"].(string)
		_, existsKey := appData["key"].(string)
		_, existsSecret := appData["secret"].(string)
		_, existsApp := appData["app"].(string)

		// Case i) ✅ All 4 fields exist → Track expiration
		if existsInVault && existsKey && existsSecret && existsApp && existsExpiration {
			expirationTime, err := time.Parse(time.RFC3339, expirationTimeStr)
			if err != nil {
				log.Printf("❌ Invalid expirationTime format in Vault for %s", app.AppName)
				continue
			}

			// Track expiration
			vc.expirationTracker[app.AppName] = expirationTime
			continue
		}

		// Case ii) ❌ All keys missing → Fetch from Apigee, write to Vault
		if !existsInVault {
			fmt.Printf("🔍 No Vault entry found for %s. Fetching keys from Apigee...\n", app.AppName)

			creds, err := app.fetchApigeeKeys()
			if err != nil {
				log.Printf("❌ Failed to fetch keys for %s: %v", app.AppName, err)
				continue
			}

			expTime := time.Now().Add(ttlDuration) // Set expiration using TTL
			vc.expirationTracker[app.AppName] = expTime

			// Write key & expiration to Vault
			err = vc.writeToVault(app, creds[0].ConsumerKey, creds[0].ConsumerSecret, expTime)
			if err != nil {
				log.Printf("❌ Failed to write to Vault for %s: %v", app.AppName, err)
			}
			continue
		}

		// Case iii) ⏳ Expiry is in the past → Reset and PATCH Vault
		if existsExpiration {
			expirationTime, err := time.Parse(time.RFC3339, expirationTimeStr)
			if err == nil && expirationTime.Before(time.Now()) {
				fmt.Printf("⏳ Expired key found for %s. Resetting expiration...\n", app.AppName)
				newExpiration := time.Now().Add(ttlDuration)
				vc.expirationTracker[app.AppName] = newExpiration

				// PATCH only expiration_time in Vault
				err := vc.patchVaultExpiration(&app, newExpiration)
				if err != nil {
					log.Printf("❌ Failed to patch expiration for %s: %v", app.AppName, err)
				}
				continue
			}
		}

		// Case iv) 🟡 Vault entry exists, but missing from expirationTracker → Refresh map
		if existsInVault && !vc.hasExpirationTrackerEntry(app.AppName) {
			fmt.Printf("⚠️ Vault entry exists for %s, but missing from expirationTracker. Refreshing...\n", app.AppName)
			expTime, _ := time.Parse(time.RFC3339, expirationTimeStr)
			vc.expirationTracker[app.AppName] = expTime
			continue
		}

		// Vault entry is missing, but expirationTracker entry exists → Log only
		if !existsInVault && vc.hasExpirationTrackerEntry(app.AppName) {
			fmt.Printf("⚠️ Stale entry: expirationTracker contains %s, but Vault entry is missing. Skipping...\n", app.AppName)
			continue
		}
	}

	// ✅ Start expiration watcher only if there are valid tracked entries
	if len(vc.expirationTracker) > 0 {
		go vc.expirationWatcher(config)
	}
}

func (vc *VaultClient) hasExpirationTrackerEntry(appName string) bool {
	_, exists := vc.expirationTracker[appName]
	return exists
}

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
				fmt.Printf("❌ Failed to read Vault for %s: %v\n", app.AppName, err)
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

func main() {
	// Initialize Apigee config and HTTP client
	if err := initializeApigeeConfig(); err != nil {
		fmt.Println("❌ Failed to initialize Apigee:", err)
		return
	}

	// Read config.yaml
	config, err := ReadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// Parse TTL duration from env variable (e.g., "30d" -> time.Duration)
	ttlStr := os.Getenv("TTL")
	ttlDuration, err = parseTTL(ttlStr)
	if err != nil {
		log.Fatalf("❌ Invalid TTL format: %v", err)
	}

	// Initialize Vault client
	vaultClient, err := NewVaultClient()
	if err != nil {
		log.Fatalf("❌ Failed to initialize Vault client: %v", err)
	}

	// 🔹 Validate config and set up expiration tracking
	vaultClient.ValidateConfig(config)

	// Block the main thread (needed for Kubernetes pod)
	select {}
}
