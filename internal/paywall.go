// Package shepherd provides the core firewall and paywall functionality for the Shepherd project
package shepherd

import (
	"fmt"
	"strings"
)

type FirewallConfig struct {
	ID      string
	Name    string
	RuleSet []string
	Enabled bool
}

type Firewool interface {
	Configure(config FirewallConfig) error
	GetRules() []string
}

type firewallImpl struct {
	rules   []string
	enabled bool
}

func NewFirewall() Firewool {
	return &firewallImpl{
		rules:   []string{},
		enabled: false,
	}
}

func (f *firewallImpl) Configure(config FirewallConfig) error {
	if !config.Enabled {
		f.enabled = false
		return nil
	}

	f.enabled = true
	f.rules = config.RuleSet
	return nil
}

func (f *firewallImpl) GetRules() []string {
	if !f.enabled {
		return []string{"Firewall is disabled"}
	}
	return f.rules
}

type PaywallConfig struct {
	ID      string
	Enabled bool
	PlanID  string
	Price   float64
}

type Paywall interface {
	Configure(config PaywallConfig) error
	GetClients() []map[string]interface{}
	ProcessBilling(request BillingRequest) error
}

type paywallImpl struct {
	clients []map[string]interface{}
	enabled bool
	planID  string
	price   float64
}

func NewPaywall() Paywall {
	return &paywallImpl{
		clients: []map[string]interface{}{},
		enabled: false,
		planID:  "basic",
		price:   0.0,
	}
}

func (p *paywallImpl) Configure(config PaywallConfig) error {
	p.enabled = config.Enabled
	p.planID = config.PlanID
	p.price = config.Price
	return nil
}

func (p *paywallImpl) GetClients() []map[string]interface{} {
	clients := make([]map[string]interface{}, len(p.clients))
	copy(clients, p.clients)
	return clients
}

func (p *paywallImpl) ProcessBilling(request BillingRequest) error {
	if !p.enabled {
		return fmt.Errorf("paywall is not enabled")
	}

	if request.Amount < p.price {
		return fmt.Errorf("amount must be at least $%.2f", p.price)
	}

	client := map[string]interface{}{
		"id":     request.ClientID,
		"name":   "Client " + strings.TrimPrefix(request.ClientID, "client_"),
		"email":  "client@azzurro.tech",
		"plan":   p.planID,
		"amount": request.Amount,
		"status": "active",
	}

	p.clients = append(p.clients, client)

	// Add to billing database (simulated)
	// In a real implementation, this would insert into the database

	return nil
}

type BillingRequest struct {
	ClientID  string
	Amount    float64
	Currency  string
	Timestamp string
}
