package rdnstest

import (
	"net/http"
	"slices"
	"time"

	redundantdns "github.com/redundantdns/go-client"
)

// SetBillingUsage sets the usage snapshot GET /v1/billing answers (for
// example managed pass-through lines); nil answers "usage": null.
func (fake *Fake) SetBillingUsage(usage *redundantdns.BillingUsage) {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()
	fake.billingUsage = usage
}

// mountBilling serves GET /v1/billing from the organization's plan (SetPlan)
// and its zones, attachments and alert channels.
func (fake *Fake) mountBilling(handle func(string, handler)) {
	handle("GET /v1/billing", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, fake.billing())
	})
}

// billing builds the billing page: the trial ("free" and "trial") or a
// plan of FakePlanCatalog, with limits as the API keeps them (-1 for
// unlimited).
func (fake *Fake) billing() redundantdns.Billing {
	catalog := FakePlanCatalog()
	limit := func(value *int) int {
		if value == nil {
			return redundantdns.Unlimited
		}
		return *value
	}
	plan := redundantdns.BillingPlan{
		ID: "trial", Name: "Trial",
		Limits:   redundantdns.BillingPlanLimits{Zones: limit(catalog.Trial.Limits.Zones), ProvidersPerZone: limit(catalog.Trial.Limits.ProvidersPerZone)},
		Channels: catalog.Trial.Channels, Features: catalog.Trial.Features,
	}
	status := redundantdns.BillingTrialing
	for _, candidate := range catalog.Plans {
		if candidate.ID != fake.plan {
			continue
		}
		plan = redundantdns.BillingPlan{
			ID: candidate.ID, Name: candidate.Name, PriceMonthlyCents: candidate.PriceMonthlyCents, Custom: candidate.Custom,
			Summary: candidate.Summary, Highlight: candidate.Highlight, Billing: candidate.Billing,
			Limits:   redundantdns.BillingPlanLimits{Zones: limit(candidate.Limits.Zones), ProvidersPerZone: limit(candidate.Limits.ProvidersPerZone)},
			Channels: candidate.Channels, Features: candidate.Features,
		}
		status = redundantdns.BillingActive
	}
	maxProviders := 0
	for _, zone := range fake.zones {
		maxProviders = max(maxProviders, len(zone.Attachments))
	}
	has := func(feature string) bool { return slices.Contains(plan.Features, feature) }
	billing := redundantdns.Billing{
		Plan: plan, Status: status, Detached: []redundantdns.BillingDetachedAttachment{},
		Limits: redundantdns.BillingLimits{
			Zones:            redundantdns.LimitUsage{Used: len(fake.zones), Limit: plan.Limits.Zones},
			ProvidersPerZone: redundantdns.LimitUsage{Used: maxProviders, Limit: plan.Limits.ProvidersPerZone},
			Channels:         redundantdns.ChannelUsage{Used: len(fake.channels), Kinds: plan.Channels},
		},
		Usage: fake.billingUsage, Gateway: "off", ManagedMarkupPercent: catalog.Managed.MarkupPercent,
		AlertHistoryDays: 30, MultiRegionProbes: has("multiRegionProbes"), AuditExport: has("auditExport"),
		BillingMode: "stripe",
	}
	if plan.ID == "business" || plan.ID == "enterprise" {
		billing.AlertHistoryDays = 90
		billing.PrioritySupport = true
	}
	if status == redundantdns.BillingTrialing {
		ends := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
		billing.TrialEndsAt, billing.TrialDays = &ends, catalog.Trial.Days
	}
	return billing
}
