package redundantdns_test

import (
	"context"
	"net/http"
	"testing"

	redundantdns "github.com/redundantdns/go-client"
	"github.com/redundantdns/go-client/rdnstest"
)

func TestBillingGet(t *testing.T) {
	ctx := context.Background()
	fake := rdnstest.NewFake(t)
	client := newClient(t, fake.URL)

	if _, err := client.Zones.Create(ctx, redundantdns.ZoneCreate{Name: "example.com"}); err != nil {
		t.Fatal(err)
	}
	billing, err := client.Billing.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if billing.Plan.ID != "trial" || billing.Status != redundantdns.BillingTrialing || billing.TrialEndsAt == nil || billing.TrialDays != 30 {
		t.Errorf("trial billing = %+v", billing)
	}
	if billing.Limits.Zones != (redundantdns.LimitUsage{Used: 1, Limit: 1}) || billing.Limits.Zones.Unlimited() {
		t.Errorf("zone limit = %+v", billing.Limits.Zones)
	}
	if billing.Usage != nil || billing.Detached == nil {
		t.Errorf("usage = %+v, detached = %v", billing.Usage, billing.Detached)
	}

	fake.SetPlan("business")
	fake.SetBillingUsage(&redundantdns.BillingUsage{
		Period: "2026-09", ManagedZones: 1,
		Managed:          []redundantdns.ManagedUsageLine{{ZoneID: "zone-1", ZoneName: "example.com", Provider: "route53", Queries: 1500000, ZoneCostCents: 50, QueryCostCents: 60, BilledCents: 132}},
		PassThroughCents: 110, BilledCents: 132,
	})
	billing, err = client.Billing.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if billing.Plan.ID != "business" || billing.Status != redundantdns.BillingActive || !billing.Limits.Zones.Unlimited() ||
		billing.Limits.Zones.Limit != redundantdns.Unlimited || !billing.AuditExport || billing.AlertHistoryDays != 90 {
		t.Errorf("business billing = %+v", billing)
	}
	if billing.Usage == nil || len(billing.Usage.Managed) != 1 || billing.Usage.Managed[0].Provider != "route53" || billing.ManagedMarkupPercent != 20 {
		t.Errorf("managed usage = %+v", billing.Usage)
	}
	requests := fake.Requests()
	if last := requests[len(requests)-1]; last.Method != http.MethodGet || last.Path != "/v1/billing" {
		t.Errorf("last request = %s %s", last.Method, last.Path)
	}
}
