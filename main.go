package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Device struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Address   string   `json:"address"`
	Key       string   `json:"key"`
	Transport string   `json:"transport"`
	Status    string   `json:"status"`
	LastSeen  string   `json:"last_seen"`
}

type FirewallRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Direction   string `json:"direction"`
	Protocol    string `json:"protocol"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Action      string `json:"action"`
	AIEnabled   bool   `json:"ai_enabled"`
	CreatedAt   string `json:"created_at"`
}

type OllamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
}

type OllamaResponse struct {
	Response string `json:"response"`
}

var (
	devices     []Device
	rules       []FirewallRule
	dataMu      sync.RWMutex
	ollamaURL   = "http://localhost:11434"
	ollamaModel = "llama3.2"
	dataDir     = "data"
)

func main() {
	os.MkdirAll(dataDir, 0755)
	loadData()

	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/api/devices", devicesHandler)
	http.HandleFunc("/api/rules", rulesHandler)
	http.HandleFunc("/api/firewall/analyze", analyzeHandler)
	http.HandleFunc("/api/ollama/status", ollamaStatusHandler)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.ListenAndServe(":8086", nil)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	dataMu.RLock()
	defer dataMu.RUnlock()
	tmpl := template.Must(template.ParseFiles("templates/index.html"))
	tmpl.Execute(w, map[string]interface{}{
		"Devices": devices,
		"Rules":   rules,
	})
}

func devicesHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		dataMu.RLock()
		json.NewEncoder(w).Encode(devices)
		dataMu.RUnlock()
	case http.MethodPost:
		var d Device
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &d)
		d.ID = fmt.Sprintf("dev_%d", time.Now().UnixNano())
		d.Status = "online"
		d.LastSeen = time.Now().Format(time.RFC3339)
		dataMu.Lock()
		devices = append(devices, d)
		saveData()
		dataMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(d)
	case http.MethodDelete:
		dataMu.Lock()
		devices = nil
		saveData()
		dataMu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}
}

func rulesHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		dataMu.RLock()
		json.NewEncoder(w).Encode(rules)
		dataMu.RUnlock()
	case http.MethodPost:
		var rule FirewallRule
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &rule)
		rule.ID = fmt.Sprintf("rule_%d", time.Now().UnixNano())
		rule.CreatedAt = time.Now().Format(time.RFC3339)
		dataMu.Lock()
		rules = append(rules, rule)
		saveData()
		dataMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(rule)
	case http.MethodDelete:
		dataMu.Lock()
		rules = nil
		saveData()
		dataMu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}
}

func analyzeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Source      string `json:"source"`
		Destination string `json:"destination"`
		Protocol    string `json:"protocol"`
		Payload     string `json:"payload"`
	}
	body, _ := io.ReadAll(r.Body)
	json.Unmarshal(body, &req)

	prompt := fmt.Sprintf(`Analyze this network traffic and determine if it's malicious or benign. Respond with only "ALLOW" or "BLOCK" and a one-sentence reason.

Source: %s
Destination: %s
Protocol: %s
Payload: %s`, req.Source, req.Destination, req.Protocol, req.Payload)

	result := queryOllama(prompt)
	decision := "ALLOW"
	if strings.Contains(strings.ToUpper(result), "BLOCK") {
		decision = "BLOCK"
	}

	resp := map[string]string{
		"decision":   decision,
		"analysis":   result,
		"source":     req.Source,
		"destination": req.Destination,
		"protocol":   req.Protocol,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func ollamaStatusHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(ollamaURL + "/api/tags")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "unavailable",
			"error":  err.Error(),
		})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(body, &result)
	result["status"] = "available"
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func queryOllama(prompt string) string {
	reqBody := OllamaRequest{
		Model:  ollamaModel,
		Prompt: prompt,
	}
	data, _ := json.Marshal(reqBody)
	resp, err := http.Post(ollamaURL+"/api/generate", "application/json", bytes.NewReader(data))
	if err != nil {
		return "Error: cannot reach Ollama - " + err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	var fullText string
	for _, line := range lines {
		var or OllamaResponse
		json.Unmarshal([]byte(line), &or)
		fullText += or.Response
	}
	return strings.TrimSpace(fullText)
}

func loadData() {
	dataMu.Lock()
	defer dataMu.Unlock()
	dData, err := os.ReadFile(filepath.Join(dataDir, "devices.json"))
	if err == nil {
		json.Unmarshal(dData, &devices)
	}
	rData, err := os.ReadFile(filepath.Join(dataDir, "rules.json"))
	if err == nil {
		json.Unmarshal(rData, &rules)
	}
}

func saveData() {
	dData, _ := json.MarshalIndent(devices, "", "  ")
	os.WriteFile(filepath.Join(dataDir, "devices.json"), dData, 0644)
	rData, _ := json.MarshalIndent(rules, "", "  ")
	os.WriteFile(filepath.Join(dataDir, "rules.json"), rData, 0644)
}
