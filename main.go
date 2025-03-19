package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

type Credential struct {
	ConsumerKey string `json:"consumerKey"`
	IssuedAt    int64  `json:"issuedAt"`
	APIProducts []struct {
		APIProduct string `json:"apiproduct"`
	} `json:"apiProducts"`
}

type AppConfig struct {
	AppName        string
	DeveloperEmail string
	Org            string
	VaultPath      string
	ConsumerKey    string
	IssuedAt       time.Time
	APIProducts    []string
	CustomAttrs    map[string]string
}

type ApigeeResponse struct {
	Credentials []Credential `json:"credentials"`
	Attributes  []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"attributes"`
}

func fetchApigeeKeys(config *AppConfig) error {
	url := fmt.Sprintf("%s/v1/organizations/%s/developers/%s/apps/%s", os.Getenv("APIGEE_URL"), config.Org, config.DeveloperEmail, config.AppName)
	fmt.Println("Fetching from URL:", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(os.Getenv("APIGEE_USERNAME"), os.Getenv("APIGEE_PASSWORD"))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var apiResp ApigeeResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return err
	}

	// Extract custom attributes
	config.CustomAttrs = make(map[string]string)
	for _, attr := range apiResp.Attributes {
		config.CustomAttrs[attr.Name] = attr.Value
	}

	// Extract credentials and sort by IssuedAt
	if len(apiResp.Credentials) == 0 {
		return fmt.Errorf("no credentials found for app %s", config.AppName)
	}

	sort.Slice(apiResp.Credentials, func(i, j int) bool {
		return apiResp.Credentials[i].IssuedAt > apiResp.Credentials[j].IssuedAt
	})

	// Take the most recent key
	latestCredential := apiResp.Credentials[0]
	config.ConsumerKey = latestCredential.ConsumerKey
	config.IssuedAt = time.UnixMilli(latestCredential.IssuedAt)

	// Extract API Products
	for _, product := range latestCredential.APIProducts {
		config.APIProducts = append(config.APIProducts, product.APIProduct)
	}

	// Print extracted values
	fmt.Println("--- Extracted Details ---")
	fmt.Println("App Name:", config.AppName)
	fmt.Println("Consumer Key:", config.ConsumerKey)
	fmt.Println("Issued At:", config.IssuedAt)
	fmt.Println("API Products:", config.APIProducts)
	fmt.Println("Custom Attributes:", config.CustomAttrs)
	fmt.Println("This will go to Vault at:", config.VaultPath)

	return nil
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

func main() {
	// Read config.yaml
	config, err := ReadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// Iterate over each app and call fetchApigeeKeys
	for _, app := range config.Apps {
		fmt.Printf("Processing app: %s (Org: %s, Email: %s, Vault: %s)\n",
			app.AppName, app.Org, app.DeveloperEmail, app.VaultPath)

		fetchApigeeKeys(&app)
	}
}
