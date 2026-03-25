package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	cfAPI "github.com/malwarebo/deter/internal/api"
	"github.com/malwarebo/deter/internal/config"
	"github.com/malwarebo/deter/internal/mitigation"
)

type CloudflareDDoSWebhook struct {
	AlertID     string     `json:"alert_id"`
	AlertType   string     `json:"alert_type"`
	ZoneID      string     `json:"zone_id"`
	EndedAt     *time.Time `json:"ended_at"`
	SentAt      *time.Time `json:"sent_at"`
	StartedAt   *time.Time `json:"started_at"`
	Description string     `json:"description"`
	AttackID    string     `json:"attack_id"`
}

type WebhookHandler struct {
	cfg      *config.Config
	cfClient *cfAPI.CloudflareClient
}

func NewWebhookHandler(cfg *config.Config, cfClient *cfAPI.CloudflareClient) *WebhookHandler {
	return &WebhookHandler{
		cfg:      cfg,
		cfClient: cfClient,
	}
}

func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.WebhookTimeout)
	defer cancel()

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("ERROR: Webhook handler failed to read body: %v", err)
		http.Error(w, "Internal server error reading request", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	payloads, err := parseWebhookPayloads(bodyBytes)
	if err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	var results []string
	for _, payload := range payloads {
		result := h.processAlert(ctx, payload)
		results = append(results, result)
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Webhook processed: %s", strings.Join(results, "; "))
}

func parseWebhookPayloads(body []byte) ([]CloudflareDDoSWebhook, error) {
	var single CloudflareDDoSWebhook
	if err := json.Unmarshal(body, &single); err == nil {
		return []CloudflareDDoSWebhook{single}, nil
	}

	var batch []CloudflareDDoSWebhook
	if err := json.Unmarshal(body, &batch); err != nil {
		return nil, fmt.Errorf("failed to parse webhook JSON as object or array: %w", err)
	}
	if len(batch) == 0 {
		return nil, fmt.Errorf("webhook array payload is empty")
	}
	return batch, nil
}

func (h *WebhookHandler) processAlert(ctx context.Context, payload CloudflareDDoSWebhook) string {
	log.Printf("INFO: Handling webhook for Alert Type: %s, Zone ID: %s, Attack ID: %s",
		payload.AlertType, payload.ZoneID, payload.AttackID)

	if payload.ZoneID != h.cfg.TargetZoneID {
		log.Printf("INFO: Ignoring webhook for non-target zone %s", payload.ZoneID)
		return fmt.Sprintf("zone %s ignored", payload.ZoneID)
	}

	kvKey := h.cfg.KVKeyPrefix + payload.ZoneID
	isAttackActive := payload.EndedAt == nil

	if isAttackActive {
		return mitigation.ActivateMitigation(ctx, h.cfg, h.cfClient, payload.ZoneID, kvKey)
	}
	return mitigation.DeactivateMitigation(ctx, h.cfg, h.cfClient, payload.ZoneID, kvKey)
}
