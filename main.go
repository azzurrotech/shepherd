// Package main implements the shepherd project - Firewall and Paywall combination
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"
)

type ShepherdServer struct {
	port string
}

type Client struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Email        string    `json:"email"`
	Plan         string    `json:"plan"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
	LastBilling  time.Time `json:"last_billing"`
	BillingCycle string    `json:"billing_cycle"`
	Features     []string  `json:"features"`
	Usage        float64   `json:"usage"`
}

type Billing struct {
	ID           string    `json:"id"`
	ClientID     string    `json:"client_id"`
	Amount       float64   `json:"amount"`
	Currency     string    `json:"currency"`
	Status       string    `json:"status"`
	DueDate      time.Time `json:"due_date"`
	PaidDate     time.Time `json:"paid_date"`
	BillingCycle string    `json:"billing_cycle"`
}

type FirewallRule struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	SourceIP    string    `json:"source_ip"`
	DestIP      string    `json:"dest_ip"`
	Port        int       `json:"port"`
	Protocol    string    `json:"protocol"`
	Action      string    `json:"action"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

type Paywall struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Cost        float64  `json:"cost"`
	Features    []string `json:"features"`
	Enabled     bool     `json:"enabled"`
	MinUsage    float64  `json:"min_usage"`
}

func main() {
	port := flag.String("port", "8084", "Port to listen on (default: 8084)")
	help := flag.Bool("help", false, "Show help message")
	version := flag.Bool("version", false, "Show version information")

	flag.Parse()

	if *help {
		fmt.Println("Usage: shepherd [options]")
		fmt.Println("  --port     Set the port to listen on (default: 8084)")
		fmt.Println("  --help     Show this help message")
		fmt.Println("  --version  Show version information")
		return
	}

	if *version {
		fmt.Println("Shepherd - Firewall and Paywall Service v1.0.0")
		fmt.Println("Advanced Security and Automated Client Billing")
		fmt.Println("Copyright 2025 Azzurro Technology Inc.")
		return
	}

	server := &ShepherdServer{port: *port}
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start shepherd server: %v", err)
	}
}

func (s *ShepherdServer) Start() error {
	fmt.Printf("Starting Shepherd - Firewall and Paywall Service on port %s\n", s.port)
	fmt.Println("Advanced Security with Client Billing")

	// Set up HTTP routes
	http.HandleFunc("/", s.homeHandler)
	http.HandleFunc("/api/clients", s.handleClients)
	http.HandleFunc("/api/clients/", s.handleClientWithID)
	http.HandleFunc("/api/billing", s.handleBilling)
	http.HandleFunc("/api/firewall/rules", s.handleFirewallRules)
	http.HandleFunc("/api/firewall/rules/", s.handleFirewallRuleWithID)
	http.HandleFunc("/health", s.healthCheckHandler)

	return http.ListenAndServe(":"+s.port, http.DefaultServeMux)
}

func (s *ShepherdServer) homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<html><body><h1>Shepherd - Firewall and Paywall Service</h1>")
	fmt.Fprintf(w, "<p>Advanced security and automated client billing</p>")
	fmt.Fprintf(w, "<ul>")
	fmt.Fprintf(w, "<li>GET /api/clients - List all clients</li>")
	fmt.Fprintf(w, "<li>POST /api/clients - Create new client</li>")
	fmt.Fprintf(w, "<li>GET /api/billing - List billing records</li>")
	fmt.Fprintf(w, "<li>POST /api/billing - Process payment</li>")
	fmt.Fprintf(w, "<li>GET /api/firewall/rules - List firewall rules</li>")
	fmt.Fprintf(w, "<li>POST /api/firewall/rules - Add firewall rule</li>")
	fmt.Fprintf(w, "<li>GET /health - Health check</li>")
	fmt.Fprintf(w, "</ul></body></html>")
}

// Client handlers
func (s *ShepherdServer) handleClients(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		s.getClientsHandler(w, r)
	case "POST":
		s.createClientHandler(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *ShepherdServer) getClientsHandler(w http.ResponseWriter, r *http.Request) {
	clients := []Client{
		{
			ID:           "client_001",
			Name:         "Acme Corporation",
			Email:        "contact@acme.com",
			Plan:         "enterprise",
			Status:       "active",
			CreatedAt:    time.Now().Add(-30 * 24 * time.Hour),
			LastBilling:  time.Now().Add(-5 * time.Hour),
			BillingCycle: "monthly",
			Features:     []string{"advanced_security", "priority_support", "custom_rules"},
			Usage:        85.5,
		},
		{
			ID:           "client_002",
			Name:         "Global Technologies",
			Email:        "info@globaltech.com",
			Plan:         "professional",
			Status:       "active",
			CreatedAt:    time.Now().Add(-15 * 24 * time.Hour),
			LastBilling:  time.Now().Add(-2 * time.Hour),
			BillingCycle: "monthly",
			Features:     []string{"standard_security", "email_support"},
			Usage:        67.3,
		},
		{
			ID:           "client_003",
			Name:         "StartupXYZ",
			Email:        "hello@startupxyz.com",
			Plan:         "basic",
			Status:       "trial",
			CreatedAt:    time.Now().Add(-5 * 24 * time.Hour),
			LastBilling:  time.Now(),
			BillingCycle: "monthly",
			Features:     []string{"basic_security"},
			Usage:        23.8,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(clients)
}

func (s *ShepherdServer) createClientHandler(w http.ResponseWriter, r *http.Request) {
	var client Client
	if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	client.ID = "client_" + fmt.Sprintf("%03d", len([]interface{}{})) // simplified ID generation
	client.CreatedAt = time.Now()
	client.Status = "active"

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Client created successfully",
		"client":  client,
	})
}

func (s *ShepherdServer) handleClientWithID(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Path[len("/api/clients/"):]
	if clientID == "" {
		http.Error(w, "Client ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case "GET":
		s.getClientHandler(w, r, clientID)
	case "PUT":
		s.updateClientHandler(w, r, clientID)
	case "DELETE":
		s.deleteClientHandler(w, r, clientID)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *ShepherdServer) getClientHandler(w http.ResponseWriter, r *http.Request, clientID string) {
	client := Client{
		ID:           clientID,
		Name:         "Sample Client",
		Email:        "sample@example.com",
		Plan:         "basic",
		Status:       "active",
		CreatedAt:    time.Now().Add(-10 * 24 * time.Hour),
		LastBilling:  time.Now().Add(-1 * time.Hour),
		BillingCycle: "monthly",
		Features:     []string{"basic_security"},
		Usage:        45.2,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(client)
}

func (s *ShepherdServer) updateClientHandler(w http.ResponseWriter, r *http.Request, clientID string) {
	var updates Client
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message":   "Client updated successfully",
		"client_id": clientID,
	})
}

func (s *ShepherdServer) deleteClientHandler(w http.ResponseWriter, r *http.Request, clientID string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message":   "Client deleted successfully",
		"client_id": clientID,
	})
}

// Billing handlers
func (s *ShepherdServer) handleBilling(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		s.getBillingHandler(w, r)
	case "POST":
		s.processBillingHandler(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *ShepherdServer) getBillingHandler(w http.ResponseWriter, r *http.Request) {
	billings := []Billing{
		{
			ID:           "bill_001",
			ClientID:     "client_001",
			Amount:       2499.00,
			Currency:     "USD",
			Status:       "paid",
			DueDate:      time.Now().Add(30 * 24 * time.Hour),
			PaidDate:     time.Now().Add(-5 * time.Hour),
			BillingCycle: "monthly",
		},
		{
			ID:           "bill_002",
			ClientID:     "client_002",
			Amount:       1499.00,
			Currency:     "USD",
			Status:       "pending",
			DueDate:      time.Now().Add(25 * time.Hour),
			PaidDate:     time.Time{},
			BillingCycle: "monthly",
		},
		{
			ID:           "bill_003",
			ClientID:     "client_003",
			Amount:       999.00,
			Currency:     "USD",
			Status:       "trial",
			DueDate:      time.Now().Add(14 * 24 * time.Hour),
			PaidDate:     time.Time{},
			BillingCycle: "monthly",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(billings)
}

func (s *ShepherdServer) processBillingHandler(w http.ResponseWriter, r *http.Request) {
	var billing Billing
	if err := json.NewDecoder(r.Body).Decode(&billing); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	billing.ID = "bill_" + fmt.Sprintf("%03d", time.Now().Nanosecond()%1000)
	billing.Status = "processing"

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":     "Billing processed successfully",
		"billing":     billing,
		"next_action": "awaiting_payment",
	})
}

// Firewall handlers
func (s *ShepherdServer) handleFirewallRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		s.getFirewallRulesHandler(w, r)
	case "POST":
		s.createFirewallRuleHandler(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *ShepherdServer) getFirewallRulesHandler(w http.ResponseWriter, r *http.Request) {
	rules := []FirewallRule{
		{
			ID:          "rule_001",
			Name:        "Block Suspicious IPs",
			Description: "Block traffic from known malicious IPs",
			SourceIP:    "192.168.1.100",
			DestIP:      "*",
			Port:        8080,
			Protocol:    "tcp",
			Action:      "block",
			Enabled:     true,
			CreatedAt:   time.Now().Add(-7 * 24 * time.Hour),
		},
		{
			ID:          "rule_002",
			Name:        "Allow Database Access",
			Description: "Allow database server access",
			SourceIP:    "*",
			DestIP:      "10.0.0.5",
			Port:        5432,
			Protocol:    "tcp",
			Action:      "allow",
			Enabled:     true,
			CreatedAt:   time.Now().Add(-5 * 24 * time.Hour),
		},
		{
			ID:          "rule_003",
			Name:        "Rate Limit API",
			Description: "Limit API endpoint rate",
			SourceIP:    "*",
			DestIP:      "*",
			Port:        443,
			Protocol:    "tcp",
			Action:      "throttle",
			Enabled:     true,
			CreatedAt:   time.Now().Add(-3 * 24 * time.Hour),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rules)
}

func (s *ShepherdServer) createFirewallRuleHandler(w http.ResponseWriter, r *http.Request) {
	var rule FirewallRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	rule.ID = "rule_" + fmt.Sprintf("%03d", time.Now().Nanosecond()%1000)
	rule.CreatedAt = time.Now()
	rule.Enabled = true

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Firewall rule created successfully",
		"rule":    rule,
	})
}

func (s *ShepherdServer) handleFirewallRuleWithID(w http.ResponseWriter, r *http.Request) {
	ruleID := r.URL.Path[len("/api/firewall/rules/"):]
	if ruleID == "" {
		http.Error(w, "Rule ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case "GET":
		s.getFirewallRuleHandler(w, r, ruleID)
	case "PUT":
		s.updateFirewallRuleHandler(w, r, ruleID)
	case "DELETE":
		s.deleteFirewallRuleHandler(w, r, ruleID)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *ShepherdServer) getFirewallRuleHandler(w http.ResponseWriter, r *http.Request, ruleID string) {
	rule := FirewallRule{
		ID:          ruleID,
		Name:        "Sample Firewall Rule",
		Description: "This is a sample firewall rule",
		SourceIP:    "*",
		DestIP:      "*",
		Port:        8080,
		Protocol:    "tcp",
		Action:      "allow",
		Enabled:     true,
		CreatedAt:   time.Now().Add(-1 * time.Hour),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rule)
}

func (s *ShepherdServer) updateFirewallRuleHandler(w http.ResponseWriter, r *http.Request, ruleID string) {
	var updates FirewallRule
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Firewall rule updated successfully",
		"rule_id": ruleID,
	})
}

func (s *ShepherdServer) deleteFirewallRuleHandler(w http.ResponseWriter, r *http.Request, ruleID string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Firewall rule deleted successfully",
		"rule_id": ruleID,
	})
}

// Health check handler
func (s *ShepherdServer) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
		"service":   "shepherd",
		"version":   "1.0.0",
		"clients":   3,
		"billing":   3,
		"rules":     3,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}
