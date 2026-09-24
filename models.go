package redundantdns

import (
	"encoding/json"
	"time"
)

// Token scopes.
const (
	ScopeZonesRead        = "zones:read"
	ScopeZonesWrite       = "zones:write"
	ScopeConnectionsRead  = "connections:read"
	ScopeConnectionsWrite = "connections:write"
)

// AllScopes lists every token scope.
var AllScopes = []string{ScopeZonesRead, ScopeZonesWrite, ScopeConnectionsRead, ScopeConnectionsWrite}

// Connection access levels.
const (
	AccessLevelZoneAdmin  = "zone_admin"
	AccessLevelZoneEditor = "zone_editor"
)

// Connection modes.
const (
	ModeBYO     = "byo"
	ModeManaged = "managed"
)

// Alert channel kinds.
const (
	ChannelEmail   = "email"
	ChannelWebhook = "webhook"
	ChannelSlack   = "slack"
)

// Attachment sync states.
const (
	StatePending = "pending"
	StateInSync  = "in_sync"
	StateDrift   = "drift"
	StateError   = "error"
)

// Zone is a canonical zone. List answers omit RecordSets.
type Zone struct {
	ZoneID       string            `json:"zoneId"`
	Name         string            `json:"name"`
	Serial       int64             `json:"serial"`
	Settings     ZoneSettings      `json:"settings"`
	NSPlan       []string          `json:"nsPlan"`
	RecordSets   []RecordSet       `json:"recordSets"`
	Attachments  []Attachment      `json:"attachments"`
	Capabilities *ZoneCapabilities `json:"capabilities,omitempty"`
	Status       *ZoneStatus       `json:"status,omitempty"`
	CreatedAt    time.Time         `json:"createdAt"`
	UpdatedAt    time.Time         `json:"updatedAt"`
}

// ZoneCapabilities is a zone's effective capability: the intersection of
// its attached providers' capabilities (nil without attachments).
type ZoneCapabilities struct {
	Capabilities
	Providers []string `json:"providers"`
}

// ZoneSettings are the zone defaults.
type ZoneSettings struct {
	DefaultTTL int `json:"defaultTtl"`
}

// ZoneCreate is the body of Zones.Create.
type ZoneCreate struct {
	Name string `json:"name"`
	// DefaultTTL is the TTL of record sets created without one (0 = the
	// server default, 300).
	DefaultTTL int `json:"defaultTtl,omitempty"`
}

// RecordSet is one (name, type) set. Name is relative to the zone, "@" for
// the apex; values are in the canonical form (see NormalizeRecordValues).
type RecordSet struct {
	Name               string          `json:"name"`
	Type               string          `json:"type"`
	TTL                int             `json:"ttl"`
	Values             []string        `json:"values"`
	ProviderExtensions json.RawMessage `json:"providerExtensions,omitempty"`
}

// RecordUpsert creates or replaces a record set. Previous renames an
// existing set (its old name and type).
type RecordUpsert struct {
	Name     string        `json:"name"`
	Type     string        `json:"type"`
	TTL      int           `json:"ttl,omitempty"`
	Values   []string      `json:"values"`
	Previous *RecordSetRef `json:"previous,omitempty"`
}

// RecordSetRef names a record set.
type RecordSetRef struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// RecordUpsertResult is the answer of Records.Upsert.
type RecordUpsertResult struct {
	RecordSet RecordSet `json:"recordSet"`
	Serial    int64     `json:"serial"`
}

// Attachment links a zone to a provider connection.
type Attachment struct {
	AttachmentID   string    `json:"attachmentId"`
	ConnectionID   string    `json:"connectionId"`
	Provider       string    `json:"provider"`
	Label          string    `json:"label,omitempty"`
	AccessLevel    string    `json:"accessLevel"`
	ProviderZoneID string    `json:"providerZoneId"`
	NameServers    []string  `json:"nameServers"`
	CreatedRemote  bool      `json:"createdRemote"`
	CreatedAt      time.Time `json:"createdAt"`
}

// AttachmentCreate is the body of Attachments.Create.
type AttachmentCreate struct {
	ConnectionID string `json:"connectionId"`
	// ProviderZoneID is the existing provider zone (required for
	// zone_editor connections, optional with AdoptExisting).
	ProviderZoneID string `json:"providerZoneId,omitempty"`
	// AdoptExisting attaches an existing provider zone instead of creating
	// one.
	AdoptExisting bool `json:"adoptExisting,omitempty"`
	// Label names the attachment (optional, up to 80 characters; the
	// connection's label is shown otherwise), e.g. the label it had before
	// a detach.
	Label string `json:"label,omitempty"`
}

// AttachResult is the answer of Attachments.Create.
type AttachResult struct {
	Attachment Attachment `json:"attachment"`
	NSPlan     []string   `json:"nsPlan"`
}

// DetachOptions controls Attachments.Delete.
type DetachOptions struct {
	// DeleteRemote also deletes the provider zone (zone_admin only).
	DeleteRemote bool
	// ConfirmName must repeat the zone name when DeleteRemote is set.
	ConfirmName string
}

// Connection is a provider connection. Credentials are never returned.
type Connection struct {
	ConnectionID    string            `json:"connectionId"`
	Provider        string            `json:"provider"`
	Mode            string            `json:"mode"`
	Label           string            `json:"label"`
	AccessLevel     string            `json:"accessLevel"`
	ScopeHints      map[string]string `json:"scopeHints"`
	CredentialsHint string            `json:"credentialsHint,omitempty"`
	Status          string            `json:"status"`
	LastCheckedAt   *time.Time        `json:"lastCheckedAt,omitempty"`
	LastError       string            `json:"lastError,omitempty"`
	CreatedAt       time.Time         `json:"createdAt"`
}

// ConnectionCreate is the body of Connections.Create. Credentials are
// write-only (route53 {accessKeyId, secretAccessKey}; oci {tenancyId,
// userId, fingerprint, privateKey}; see Account.Providers for each
// provider's fields).
type ConnectionCreate struct {
	Provider    string            `json:"provider"`
	Mode        string            `json:"mode,omitempty"`
	Label       string            `json:"label,omitempty"`
	AccessLevel string            `json:"accessLevel,omitempty"`
	Credentials map[string]string `json:"credentials,omitempty"`
	ScopeHints  map[string]string `json:"scopeHints,omitempty"`
}

// ConnectionCreateResult is the answer of Connections.Create. Deferred
// means the credentials test did not run yet (Connection.Status stays
// pending until it does).
type ConnectionCreateResult struct {
	Connection Connection `json:"connection"`
	Deferred   bool       `json:"deferred"`
}

// TestResult is the outcome of a connection test.
type TestResult struct {
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Deferred bool   `json:"deferred,omitempty"`
}

// ConnectionTestResult is the answer of Connections.Test.
type ConnectionTestResult struct {
	Connection Connection `json:"connection"`
	Result     TestResult `json:"result"`
}

// Provider describes an available DNS provider.
type Provider struct {
	ID               string       `json:"id"`
	CredentialFields []string     `json:"credentialFields"`
	SecretFields     []string     `json:"secretFields"`
	ScopeFields      []string     `json:"scopeFields"`
	ZoneIDLabel      string       `json:"zoneIdLabel"`
	Capabilities     Capabilities `json:"capabilities"`
	HasDocs          bool         `json:"hasDocs"`
	Managed          bool         `json:"managed"`
}

// Capabilities is what a provider supports.
type Capabilities struct {
	RecordTypes     []string `json:"recordTypes"`
	MinTTL          int      `json:"minTtl"`
	MaxTTL          int      `json:"maxTtl"`
	Wildcard        bool     `json:"wildcard"`
	ApexNSEditable  bool     `json:"apexNsEditable"`
	MaxValuesPerSet int      `json:"maxValuesPerSet"`
	TXTMaxLen       int      `json:"txtMaxLen"`
	CNAMEAtApex     bool     `json:"cnameAtApex"`
}

// ZoneStatus is the data-plane status of a zone.
type ZoneStatus struct {
	OrgID       string                      `json:"orgId"`
	ZoneID      string                      `json:"zoneId"`
	Attachments map[string]AttachmentStatus `json:"attachments"`
	Delegation  *Delegation                 `json:"delegation,omitempty"`
	Probes      map[string]ProbeResult      `json:"probes,omitempty"`
	ProbedAt    *time.Time                  `json:"probedAt,omitempty"`
	UpdatedAt   time.Time                   `json:"updatedAt"`
}

// AttachmentStatus is the sync state of one attachment.
type AttachmentStatus struct {
	AttachmentID  string       `json:"attachmentId"`
	State         string       `json:"state"`
	AppliedSerial int64        `json:"appliedSerial"`
	LastSyncAt    *time.Time   `json:"lastSyncAt,omitempty"`
	LastVerifyAt  *time.Time   `json:"lastVerifyAt,omitempty"`
	LastDiff      *DiffSummary `json:"lastDiff,omitempty"`
	LastError     string       `json:"lastError,omitempty"`
	Health        string       `json:"health,omitempty"`
	DownStreak    int          `json:"downStreak,omitempty"`
	LastProbeAt   *time.Time   `json:"lastProbeAt,omitempty"`
	UpdatedAt     time.Time    `json:"updatedAt"`
}

// DiffSummary counts the changes between two versions of a zone.
type DiffSummary struct {
	Create int `json:"create"`
	Update int `json:"update"`
	Delete int `json:"delete"`
	Keys   struct {
		Create []string `json:"create"`
		Update []string `json:"update"`
		Delete []string `json:"delete"`
	} `json:"keys"`
}

// ProbeResult is the last probe of one nameserver.
type ProbeResult struct {
	NameServer   string    `json:"nameServer"`
	AttachmentID string    `json:"attachmentId"`
	Reachable    bool      `json:"reachable"`
	Transport    string    `json:"transport,omitempty"`
	LatencyMs    int       `json:"latencyMs"`
	Serial       int64     `json:"serial,omitempty"`
	Match        bool      `json:"match"`
	Mismatches   []string  `json:"mismatches,omitempty"`
	Sampled      int       `json:"sampled,omitempty"`
	Error        string    `json:"error,omitempty"`
	ProbedAt     time.Time `json:"probedAt"`
}

// Delegation is a delegation check: the parent NS set against the NS plan.
type Delegation struct {
	State     string             `json:"state"`
	SeenNS    []string           `json:"seenNs"`
	Missing   []string           `json:"missing"`
	Extra     []string           `json:"extra"`
	NSPlan    []string           `json:"nsPlan"`
	Answers   []DelegationAnswer `json:"answers,omitempty"`
	CheckedAt time.Time          `json:"checkedAt"`
}

// DelegationAnswer is one parent nameserver's answer.
type DelegationAnswer struct {
	NameServer string   `json:"nameServer"`
	Responded  bool     `json:"responded"`
	NS         []string `json:"ns"`
	LatencyMs  int      `json:"latencyMs"`
	Error      string   `json:"error,omitempty"`
}

// Jobs is the answer of the job routes (reconcile, verify, adopt).
type Jobs struct {
	JobIDs []string `json:"jobIds"`
}

// JournalEntry is one serial change of a zone.
type JournalEntry struct {
	ZoneID  string       `json:"zoneId"`
	Serial  int64        `json:"serial"`
	Action  string       `json:"action"`
	ActorID string       `json:"actorId"`
	At      time.Time    `json:"at"`
	Changes *DiffSummary `json:"changes,omitempty"`
}

// AlertRule is an alert rule with its effective threshold.
type AlertRule struct {
	Kind         string `json:"kind"`
	Enabled      bool   `json:"enabled"`
	Threshold    int    `json:"threshold,omitempty"`
	MinThreshold int    `json:"minThreshold,omitempty"`
	MaxThreshold int    `json:"maxThreshold,omitempty"`
}

// AlertRuleUpdate is the body of Alerts.UpdateRule.
type AlertRuleUpdate struct {
	Enabled   *bool `json:"enabled,omitempty"`
	Threshold *int  `json:"threshold,omitempty"`
}

// AlertChannel is a notification channel. Secrets are never returned; a
// Slack target is masked.
type AlertChannel struct {
	ChannelID string    `json:"channelId"`
	Kind      string    `json:"kind"`
	Label     string    `json:"label"`
	Target    string    `json:"target"`
	Enabled   bool      `json:"enabled"`
	HasSecret bool      `json:"hasSecret"`
	CreatedAt time.Time `json:"createdAt"`
}

// AlertChannelCreate is the body of Alerts.CreateChannel.
type AlertChannelCreate struct {
	Kind   string `json:"kind"`
	Label  string `json:"label,omitempty"`
	Target string `json:"target"`
	// Secret is the webhook signing secret (16-256 chars); generated when
	// empty.
	Secret string `json:"secret,omitempty"`
}

// AlertChannelCreateResult is the answer of Alerts.CreateChannel. Secret
// is the webhook signing secret, returned only here.
type AlertChannelCreateResult struct {
	Channel AlertChannel `json:"channel"`
	Secret  string       `json:"secret,omitempty"`
}

// AlertTestResult is the answer of Alerts.TestChannel.
type AlertTestResult struct {
	OK       bool   `json:"ok"`
	Attempts int    `json:"attempts"`
	Error    string `json:"error,omitempty"`
}

// AlertEvent is one alert (firing or resolved).
type AlertEvent struct {
	EventID         string            `json:"eventId"`
	OrgID           string            `json:"orgId"`
	Rule            string            `json:"rule"`
	State           string            `json:"state"`
	ZoneID          string            `json:"zoneId"`
	ZoneName        string            `json:"zoneName"`
	AttachmentID    string            `json:"attachmentId,omitempty"`
	AttachmentLabel string            `json:"attachmentLabel,omitempty"`
	DedupeKey       string            `json:"dedupeKey"`
	Summary         string            `json:"summary"`
	FirstSeenAt     time.Time         `json:"firstSeenAt"`
	LastSeenAt      time.Time         `json:"lastSeenAt"`
	ResolvedAt      *time.Time        `json:"resolvedAt,omitempty"`
	ResolvedBy      string            `json:"resolvedBy,omitempty"`
	AckedAt         *time.Time        `json:"ackedAt,omitempty"`
	AckedBy         string            `json:"ackedBy,omitempty"`
	Transitions     []AlertTransition `json:"transitions,omitempty"`
}

// AlertTransition is one state change of an event.
type AlertTransition struct {
	State  string    `json:"state"`
	At     time.Time `json:"at"`
	By     string    `json:"by,omitempty"`
	Reason string    `json:"reason,omitempty"`
}

// AlertEventFilter filters Alerts.ListEvents. Zero fields are ignored;
// Limit is capped at 500 by the server.
type AlertEventFilter struct {
	ZoneID string
	Rule   string
	State  string
	Limit  int
}

// AuditEntry is one audit log event.
type AuditEntry struct {
	ID      string         `json:"id"`
	OrgID   string         `json:"orgId"`
	ActorID string         `json:"actorId"`
	Source  string         `json:"source"`
	Action  string         `json:"action"`
	ZoneID  string         `json:"zoneId,omitempty"`
	Target  AuditTarget    `json:"target"`
	Details map[string]any `json:"details,omitempty"`
	IP      string         `json:"ip,omitempty"`
	At      time.Time      `json:"at"`
}

// AuditTarget is what an audit event acted on.
type AuditTarget struct {
	Type  string `json:"type"`
	ID    string `json:"id"`
	Label string `json:"label,omitempty"`
}

// Me is the caller and their organizations.
type Me struct {
	User User         `json:"user"`
	Orgs []OrgSummary `json:"orgs"`
}

// User is the authenticated user. Kind is session, pat or oauth.
type User struct {
	UserID        string `json:"userId"`
	Email         string `json:"email"`
	PlatformAdmin bool   `json:"platformAdmin"`
	Kind          string `json:"kind,omitempty"`
}

// OrgSummary is an organization and the caller's role in it.
type OrgSummary struct {
	OrgID string `json:"orgId"`
	Name  string `json:"name"`
	Plan  string `json:"plan"`
	Role  string `json:"role"`
}

// LegalVersions are the current Terms of Service and Privacy Policy
// versions (YYYY-MM-DD).
type LegalVersions struct {
	Terms   string `json:"terms"`
	Privacy string `json:"privacy"`
}

// LegalStatus is the caller's acceptance of the legal documents.
type LegalStatus struct {
	Current  LegalVersions    `json:"current"`
	Accepted *LegalAcceptance `json:"accepted"`
	Required bool             `json:"required"`
}

// LegalAcceptance records an acceptance.
type LegalAcceptance struct {
	AcceptedTermsVersion   string    `json:"acceptedTermsVersion"`
	AcceptedPrivacyVersion string    `json:"acceptedPrivacyVersion"`
	AcceptedAt             time.Time `json:"acceptedAt"`
	IP                     string    `json:"ip,omitempty"`
}

// Token is a personal access token record (the secret is returned only by
// Tokens.Create).
type Token struct {
	TokenID     string     `json:"tokenId"`
	UserID      string     `json:"userId"`
	Name        string     `json:"name"`
	Prefix      string     `json:"prefix"`
	Scopes      []string   `json:"scopes"`
	IPAllowlist []string   `json:"ipAllowlist"`
	CreatedAt   time.Time  `json:"createdAt"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
	RevokedAt   *time.Time `json:"revokedAt,omitempty"`
}

// TokenCreate is the body of Tokens.Create.
type TokenCreate struct {
	Name          string   `json:"name"`
	Scopes        []string `json:"scopes"`
	ExpiresInDays int      `json:"expiresInDays,omitempty"`
	IPAllowlist   []string `json:"ipAllowlist,omitempty"`
}

// TokenCreateResult is the answer of Tokens.Create. Token (rdns_...) is
// shown only once.
type TokenCreateResult struct {
	Record Token  `json:"record"`
	Token  string `json:"token"`
}
