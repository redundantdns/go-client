package redundantdns

import (
	"context"
	"net/http"
	"slices"
)

// PlansService reads the public plan catalog (GET /v1/plans, no
// authentication; API docs "Plans and billing").
type PlansService struct{ client *Client }

// Catalog publication states.
const (
	CatalogDraft      = "draft"
	CatalogComingSoon = "coming_soon"
	CatalogPublished  = "published"
)

// Billing intervals.
const (
	IntervalMonthly = "monthly"
	IntervalYearly  = "yearly"
)

// PlanLimits are a plan's limits; nil means unlimited.
type PlanLimits struct {
	Zones            *int `json:"zones"`
	ProvidersPerZone *int `json:"providersPerZone"`
}

// PlanTrial is the trial every new organization starts on: a note of the
// catalog, not a plan (never listed in Plans, never sold).
type PlanTrial struct {
	Days     int        `json:"days"`
	Limits   PlanLimits `json:"limits"`
	Modes    []string   `json:"modes"`
	Alerts   []string   `json:"alerts"`
	Access   []string   `json:"access"`
	Channels []string   `json:"channels"`
	Features []string   `json:"features"`
}

// PlanManaged is the managed pass-through pricing.
type PlanManaged struct {
	MarkupPercent int    `json:"markupPercent"`
	Billing       string `json:"billing"`
}

// PlanGrace is the past-due policy in days: read-only after
// ReadOnlyAfterDays past due, attachments detached DetachAfterDays later.
type PlanGrace struct {
	ReadOnlyAfterDays *int `json:"readOnlyAfterDays"`
	DetachAfterDays   *int `json:"detachAfterDays"`
}

// ManagedProviderCost is a managed provider's list price.
type ManagedProviderCost struct {
	ZoneMonthUSD       float64 `json:"zoneMonthUsd"`
	PerMillionQueryUSD float64 `json:"perMillionQueriesUsd"`
}

// CatalogPlan is one plan of the catalog.
type CatalogPlan struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// PriceMonthly is in US dollars; nil for custom (contract) plans.
	PriceMonthly *float64   `json:"priceMonthly"`
	Custom       bool       `json:"custom"`
	Highlight    bool       `json:"highlight,omitempty"`
	Billing      string     `json:"billing,omitempty"`
	Summary      string     `json:"summary"`
	Limits       PlanLimits `json:"limits"`
	Modes        []string   `json:"modes"`
	Alerts       []string   `json:"alerts"`
	Access       []string   `json:"access"`
	// PriceYearlyCents is set only while the yearly interval is on sale
	// and the plan has a yearly price.
	PriceMonthlyCents int64  `json:"priceMonthlyCents"`
	PriceYearlyCents  *int64 `json:"priceYearlyCents,omitempty"`
	Purchasable       bool   `json:"purchasable"`
	// Available: the plan can be bought now (none before the catalog is
	// published).
	Available bool     `json:"available"`
	Channels  []string `json:"channels"`
	Features  []string `json:"features"`
	// AuditRetentionDays is how long the audit trail is kept on write-once
	// storage (nil: no promise); AuditRetentionCustom marks a custom
	// retention (Enterprise).
	AuditRetentionDays   *int `json:"auditRetentionDays"`
	AuditRetentionCustom bool `json:"auditRetentionCustom,omitempty"`
}

// PlanCatalog is the public plan catalog.
type PlanCatalog struct {
	Source    string `json:"source"`
	Status    string `json:"status"`
	UpdatedAt string `json:"updatedAt"`
	Currency  string `json:"currency"`
	// Intervals are the billing intervals on sale, monthly first.
	Intervals []string `json:"intervals"`
	// AnnualFreeMonths is the yearly discount, meaningful only while
	// Intervals lists IntervalYearly.
	AnnualFreeMonths int                            `json:"annualFreeMonths"`
	Managed          PlanManaged                    `json:"managed"`
	Grace            PlanGrace                      `json:"grace"`
	Trial            PlanTrial                      `json:"trial"`
	Plans            []CatalogPlan                  `json:"plans"`
	ManagedCosts     map[string]ManagedProviderCost `json:"managedCosts,omitempty"`
}

// Plan returns the plan with the id (nil when not listed).
func (catalog *PlanCatalog) Plan(id string) *CatalogPlan {
	for index := range catalog.Plans {
		if catalog.Plans[index].ID == id {
			return &catalog.Plans[index]
		}
	}
	return nil
}

// IntervalOnSale reports whether a billing interval is on sale.
func (catalog *PlanCatalog) IntervalOnSale(interval string) bool {
	return slices.Contains(catalog.Intervals, interval)
}

// Catalog returns the public plan catalog.
func (service *PlansService) Catalog(ctx context.Context) (*PlanCatalog, error) {
	var catalog PlanCatalog
	if err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/plans"}, &catalog); err != nil {
		return nil, err
	}
	if len(catalog.Intervals) == 0 {
		// Older deployments did not list the intervals: monthly only.
		catalog.Intervals = []string{IntervalMonthly}
	}
	return &catalog, nil
}
