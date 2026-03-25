package api

import (
	"context"
	"fmt"
	"log"

	"github.com/cloudflare/cloudflare-go"
	deterConfig "github.com/malwarebo/deter/internal/config"
)

type CloudflareClient struct {
	api       *cloudflare.API
	accountID string
}

func NewCloudflareClient(cfg *deterConfig.Config) (*CloudflareClient, error) {
	api, err := cloudflare.NewWithAPIToken(cfg.CfAPIToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create cloudflare client: %w", err)
	}

	return &CloudflareClient{
		api:       api,
		accountID: cfg.CfAccountID,
	}, nil
}

func (c *CloudflareClient) SetSecurityLevel(ctx context.Context, zoneID, level string) error {
	log.Printf("API CALL: Setting security level for zone %s to %s", zoneID, level)
	rc := cloudflare.ZoneIdentifier(zoneID)

	params := cloudflare.UpdateZoneSettingParams{
		Name:  "security_level",
		Value: level,
	}

	_, err := c.api.UpdateZoneSetting(ctx, rc, params)
	if err != nil {
		return fmt.Errorf("failed to update zone setting 'security_level' to '%s' for zone %s: %w", level, zoneID, err)
	}
	return nil
}

func (c *CloudflareClient) WriteKvValue(ctx context.Context, namespaceID, key, value string) error {
	log.Printf("API CALL: Writing to KV Namespace %s: Key=%s, Value=%s", namespaceID, key, value)
	rc := cloudflare.AccountIdentifier(c.accountID)

	params := cloudflare.WriteWorkersKVEntryParams{
		NamespaceID: namespaceID,
		Key:         key,
		Value:       []byte(value),
	}

	_, err := c.api.WriteWorkersKVEntry(ctx, rc, params)
	if err != nil {
		return fmt.Errorf("failed to write KV entry (Namespace: %s, Key: %s): %w", namespaceID, key, err)
	}
	return nil
}
