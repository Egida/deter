package mitigation

import (
	"context"
	"log"
	"strings"
	"sync"

	cfAPI "github.com/malwarebo/deter/internal/api"
	"github.com/malwarebo/deter/internal/config"
)

type State struct {
	mu     sync.Mutex
	active map[string]bool
}

var state = &State{active: make(map[string]bool)}

func IsActive(zoneID string) bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.active[zoneID]
}

func ActivateMitigation(ctx context.Context, cfg *config.Config, cfClient *cfAPI.CloudflareClient, zoneID, kvKey string) string {
	state.mu.Lock()
	if state.active[zoneID] {
		state.mu.Unlock()
		log.Printf("INFO: Mitigation already active for zone %s, skipping", zoneID)
		return "Activated Mitigation (Already Active)"
	}
	state.mu.Unlock()

	log.Printf("INFO: Activating mitigations for zone %s", zoneID)
	actionStatus := []string{}

	err := cfClient.WriteKvValue(ctx, cfg.KVNamespaceID, kvKey, "active")
	if err != nil {
		log.Printf("ERROR: Failed to signal worker via KV (active): %v", err)
		actionStatus = append(actionStatus, "KV Signal FAILED")
	} else {
		log.Printf("INFO: Successfully signaled Worker via KV: %s = active", kvKey)
		actionStatus = append(actionStatus, "KV Signaled")
	}

	err = cfClient.SetSecurityLevel(ctx, zoneID, "under_attack")
	if err != nil {
		log.Printf("ERROR: Failed to set security level to 'under_attack': %v", err)
		actionStatus = append(actionStatus, "Security Level FAILED")
	} else {
		log.Printf("INFO: Successfully set security level to 'under_attack' for zone %s", zoneID)
		actionStatus = append(actionStatus, "Security Level Set")
	}

	state.mu.Lock()
	state.active[zoneID] = true
	state.mu.Unlock()

	return "Activated Mitigation (" + strings.Join(actionStatus, ", ") + ")"
}

func DeactivateMitigation(ctx context.Context, cfg *config.Config, cfClient *cfAPI.CloudflareClient, zoneID, kvKey string) string {
	state.mu.Lock()
	if !state.active[zoneID] {
		state.mu.Unlock()
		log.Printf("INFO: Mitigation already inactive for zone %s, skipping", zoneID)
		return "Deactivated Mitigation (Already Inactive)"
	}
	state.mu.Unlock()

	log.Printf("INFO: Deactivating mitigations for zone %s", zoneID)
	actionStatus := []string{}

	err := cfClient.WriteKvValue(ctx, cfg.KVNamespaceID, kvKey, "inactive")
	if err != nil {
		log.Printf("ERROR: Failed to signal worker via KV (inactive): %v", err)
		actionStatus = append(actionStatus, "KV Signal FAILED")
	} else {
		log.Printf("INFO: Successfully signaled Worker via KV: %s = inactive", kvKey)
		actionStatus = append(actionStatus, "KV Signaled")
	}

	err = cfClient.SetSecurityLevel(ctx, zoneID, cfg.DefaultSecLevel)
	if err != nil {
		log.Printf("ERROR: Failed to revert security level to '%s': %v", cfg.DefaultSecLevel, err)
		actionStatus = append(actionStatus, "Security Level FAILED")
	} else {
		log.Printf("INFO: Successfully reverted security level to '%s' for zone %s", cfg.DefaultSecLevel, zoneID)
		actionStatus = append(actionStatus, "Security Level Set")
	}

	state.mu.Lock()
	state.active[zoneID] = false
	state.mu.Unlock()

	return "Deactivated Mitigation (" + strings.Join(actionStatus, ", ") + ")"
}