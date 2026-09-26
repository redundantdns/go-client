package redundantdns

import (
	"context"
	"net/http"
	"time"
)

// BillingService reads the organization's billing page (GET /v1/billing:
// viewer + zones:read). Checkout and the customer portal need a dashboard
// session and are not part of the client.
type BillingService struct{ client *Client }

// Unlimited is the value of a billing limit without a cap (GET /v1/billing
// keeps -1, unlike the public catalog, which answers null).
const Unlimited = -1

// Billing statuses (Billing.Status).
const (
	BillingActive   = "active"
	BillingTrialing = "trialing"
	BillingPastDue  = "past_due"
	BillingReadOnly = "read_only"
	BillingDetached = "detached"
	BillingCanceled = "canceled"
)

// Billing is the organization's plan, billing status, limits with their
// usage and the managed providers' pass-through of the current period.
type Billing struct {
	Plan     BillingPlan `json:"plan"`
	Status   string      `json:"status"`
	Interval string      `json:"interval,omitempty"`

	CurrentPeriodEnd *time.Time `json:"currentPeriodEnd,omitempty"`
	NextInvoiceAt    *time.Time `json:"nextInvoiceAt,omitempty"`
	PastDueSince     *time.Time `json:"pastDueSince,omitempty"`
	GraceEndsAt      *time.Time `json:"graceEndsAt,omitempty"`
	ReadOnlySince    *time.Time `json:"readOnlySince,omitempty"`
	// ReadOnlyReason is unpaid, trial_ended or canceled; empty when the
	// organization is not read-only.
	ReadOnlyReason string `json:"readOnlyReason,omitempty"`

	// TrialEndsAt, TrialDays and TrialNotices (milestone to send time) are
	// set on the trial plan only.
	TrialEndsAt  *time.Time           `json:"trialEndsAt,omitempty"`
	TrialDays    int                  `json:"trialDays,omitempty"`
	TrialNotices map[string]time.Time `json:"trialNotices,omitempty"`

	// DetachAt is when a read-only organization's attachments are
	// detached; Detached lists the detached ones not attached again.
	DetachAt      *time.Time                  `json:"detachAt,omitempty"`
	DetachedSince *time.Time                  `json:"detachedSince,omitempty"`
	Detached      []BillingDetachedAttachment `json:"detached"`

	CancelAtPeriodEnd bool       `json:"cancelAtPeriodEnd"`
	CancelAt          *time.Time `json:"cancelAt,omitempty"`
	// StripeSubscriptionID is masked to its last six characters (owners
	// and admins only).
	StripeSubscriptionID string `json:"stripeSubscriptionId,omitempty"`
	HasSubscription      bool   `json:"hasSubscription"`
	HasCustomer          bool   `json:"hasCustomer"`
	LastInvoiceURL       string `json:"lastInvoiceUrl,omitempty"`

	Limits BillingLimits `json:"limits"`
	// Usage is the current period's snapshot, managed pass-through lines
	// included (nil before the first snapshot).
	Usage                *BillingUsage `json:"usage"`
	Gateway              string        `json:"gateway"`
	ManagedMarkupPercent int           `json:"managedMarkupPercent"`
	Source               string        `json:"source,omitempty"`

	PrioritySupport   bool `json:"prioritySupport"`
	AlertHistoryDays  int  `json:"alertHistoryDays"`
	MultiRegionProbes bool `json:"multiRegionProbes"`
	AuditExport       bool `json:"auditExport"`

	// BillingMode is stripe, comped or manual.
	BillingMode      string                 `json:"billingMode"`
	CompedReason     string                 `json:"compedReason,omitempty"`
	CompedUntil      *time.Time             `json:"compedUntil,omitempty"`
	ManualInvoices   []BillingManualInvoice `json:"manualInvoices,omitempty"`
	Discount         *BillingDiscount       `json:"discount,omitempty"`
	BillingIdentity  *BillingIdentity       `json:"billingIdentity,omitempty"`
	CustomPrice      *BillingCustomPrice    `json:"customPrice,omitempty"`
	CollectionMethod string                 `json:"collectionMethod,omitempty"`
}

// BillingPlan is the organization's plan as GET /v1/billing answers it
// (limits use Unlimited, not null).
type BillingPlan struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	PriceMonthlyCents int64             `json:"priceMonthlyCents"`
	PriceYearlyCents  int64             `json:"priceYearlyCents,omitempty"`
	Custom            bool              `json:"custom,omitempty"`
	Summary           string            `json:"summary,omitempty"`
	Highlight         bool              `json:"highlight,omitempty"`
	Billing           string            `json:"billing,omitempty"`
	Limits            BillingPlanLimits `json:"limits"`
	Channels          []string          `json:"channels"`
	Features          []string          `json:"features"`
}

// BillingPlanLimits are the plan's caps; Unlimited means no cap.
type BillingPlanLimits struct {
	Zones            int `json:"zones"`
	ProvidersPerZone int `json:"providersPerZone"`
}

// BillingLimits are the plan's limits with the organization's usage.
type BillingLimits struct {
	Zones LimitUsage `json:"zones"`
	// ProvidersPerZone.Used is the largest attachment count of one zone.
	ProvidersPerZone LimitUsage   `json:"providersPerZone"`
	Channels         ChannelUsage `json:"channels"`
}

// LimitUsage is a limit and how much of it is used; Limit is Unlimited
// when there is no cap.
type LimitUsage struct {
	Used  int `json:"used"`
	Limit int `json:"limit"`
}

// Unlimited reports whether the limit has no cap.
func (usage LimitUsage) Unlimited() bool { return usage.Limit < 0 }

// ChannelUsage is the number of alert channels and the kinds the plan
// allows.
type ChannelUsage struct {
	Used  int      `json:"used"`
	Kinds []string `json:"kinds"`
}

// BillingUsage is the usage snapshot of a billing period.
type BillingUsage struct {
	Period         string    `json:"period"`
	From           time.Time `json:"from"`
	To             time.Time `json:"to"`
	Zones          int       `json:"zones"`
	Attachments    int       `json:"attachments"`
	ManagedZones   int       `json:"managedZones"`
	ManagedQueries float64   `json:"managedQueries"`
	// Managed are the managed attachments' pass-through lines.
	Managed []ManagedUsageLine `json:"managed"`
	// PassThroughCents is the providers' cost; BilledCents adds the markup.
	PassThroughCents int64     `json:"passThroughCents"`
	BilledCents      int64     `json:"billedCents"`
	ComputedAt       time.Time `json:"computedAt"`
}

// ManagedUsageLine is one managed attachment's pass-through in a period.
type ManagedUsageLine struct {
	ZoneID         string  `json:"zoneId"`
	ZoneName       string  `json:"zoneName"`
	Provider       string  `json:"provider"`
	Queries        float64 `json:"queries"`
	ZoneCostCents  int64   `json:"zoneCostCents"`
	QueryCostCents int64   `json:"queryCostCents"`
	BilledCents    int64   `json:"billedCents"`
}

// BillingDetachedAttachment is an attachment the billing job detached,
// with what it takes to attach the same provider zone again.
type BillingDetachedAttachment struct {
	ZoneID         string    `json:"zoneId"`
	ZoneName       string    `json:"zoneName"`
	AttachmentID   string    `json:"attachmentId"`
	ConnectionID   string    `json:"connectionId"`
	Provider       string    `json:"provider"`
	AccessLevel    string    `json:"accessLevel"`
	ProviderZoneID string    `json:"providerZoneId"`
	Label          string    `json:"label,omitempty"`
	DetachedAt     time.Time `json:"detachedAt"`
}

// BillingManualInvoice is an invoice recorded by an operator (manual
// billing mode); amounts are in the currency's minor unit.
type BillingManualInvoice struct {
	Number      int        `json:"number"`
	AmountCents int64      `json:"amountCents"`
	Currency    string     `json:"currency"`
	Reference   string     `json:"reference"`
	IssuedAt    time.Time  `json:"issuedAt"`
	DueAt       time.Time  `json:"dueAt"`
	PaidAt      *time.Time `json:"paidAt,omitempty"`
	Note        string     `json:"note,omitempty"`
}

// BillingDiscount is the coupon on the subscription.
type BillingDiscount struct {
	Coupon           string     `json:"coupon"`
	Name             string     `json:"name,omitempty"`
	PercentOff       float64    `json:"percentOff,omitempty"`
	AmountOffCents   int64      `json:"amountOffCents,omitempty"`
	Currency         string     `json:"currency,omitempty"`
	Duration         string     `json:"duration,omitempty"`
	DurationInMonths int64      `json:"durationInMonths,omitempty"`
	PromotionCode    string     `json:"promotionCode,omitempty"`
	Start            *time.Time `json:"start,omitempty"`
	End              *time.Time `json:"end,omitempty"`
}

// BillingIdentity is the customer's billing identity (printed on invoices).
type BillingIdentity struct {
	Name    string         `json:"name,omitempty"`
	Email   string         `json:"email,omitempty"`
	Country string         `json:"country,omitempty"`
	TaxIDs  []BillingTaxID `json:"taxIds,omitempty"`
}

// BillingTaxID is one tax id of the customer (eu_vat, us_ein, br_cnpj...).
type BillingTaxID struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// BillingCustomPrice is the monthly price of an invoiced Enterprise
// subscription.
type BillingCustomPrice struct {
	AmountCents int64  `json:"amountCents"`
	Currency    string `json:"currency"`
}

// Get returns the organization's billing page.
func (service *BillingService) Get(ctx context.Context) (*Billing, error) {
	var billing Billing
	if err := service.client.do(ctx, request{method: http.MethodGet, path: "/v1/billing"}, &billing); err != nil {
		return nil, err
	}
	return &billing, nil
}
