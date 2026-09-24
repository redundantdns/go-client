package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"

	redundantdns "github.com/redundantdns/go-client"
)

const loginUsage = `rdnsctl login [--base-url URL] [--email EMAIL] [--code CODE] [--org ORG_ID]
                     [--accept-terms] [--token-name NAME] [--expires-days N] [--scopes a,b]
       rdnsctl login --token rdns_... [--base-url URL]

The first form signs in like the dashboard: an e-mailed one-time code, the
Terms of Service and Privacy Policy when not yet accepted, then a personal
access token (client "cli") is created for the chosen organization and
saved. The second form saves an existing token after checking it. For the
Terraform provider, see rdnsctl terraform login.`

func runLogin(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("login", shared)
	email := flags.String("email", "", "account e-mail")
	code := flags.String("code", "", "the e-mailed code (prompted when empty)")
	acceptTerms := flags.Bool("accept-terms", false, "accept the current Terms of Service and Privacy Policy without prompting")
	tokenName := flags.String("token-name", "", "name of the token to create")
	expiresDays := flags.Int("expires-days", 90, "token lifetime in days (0 = no expiry)")
	scopes := flags.String("scopes", strings.Join(redundantdns.AllScopes, ","), "token scopes, comma separated")
	positionals, err := parseArgs(flags, args)
	if err != nil {
		return err
	}
	if err := expectArgs(positionals, 0, loginUsage); err != nil {
		return err
	}
	path, err := cli.configPath(shared)
	if err != nil {
		return err
	}
	saved, err := loadConfig(path)
	if err != nil {
		return err
	}
	baseURL := firstNonEmpty(shared.baseURL, cli.getenv("RDNS_BASE_URL"), saved.BaseURL, redundantdns.DefaultBaseURL)
	if shared.token != "" {
		return cli.saveExistingToken(ctx, path, baseURL, shared)
	}

	anonymous, err := redundantdns.New(redundantdns.WithBaseURL(baseURL), redundantdns.WithUserAgent("rdnsctl/"+version))
	if err != nil {
		return err
	}
	if *email == "" {
		if *email, err = cli.prompt("E-mail: "); err != nil {
			return err
		}
	}
	if *code == "" {
		if err := anonymous.Auth.RequestCode(ctx, *email); err != nil {
			return fmt.Errorf("request a login code: %w", err)
		}
		fmt.Fprintf(cli.stderr, "A login code was sent to %s.\n", *email)
		if *code, err = cli.prompt("Code: "); err != nil {
			return err
		}
	}
	session, err := anonymous.Auth.VerifyCode(ctx, *email, *code)
	if err != nil {
		return fmt.Errorf("verify the code: %w", err)
	}
	org, err := cli.chooseOrg(session.Orgs, shared.org)
	if err != nil {
		return err
	}
	sessionClient, err := redundantdns.New(
		redundantdns.WithBaseURL(baseURL), redundantdns.WithSession(session.Token),
		redundantdns.WithOrg(org.OrgID), redundantdns.WithUserAgent("rdnsctl/"+version),
	)
	if err != nil {
		return err
	}
	if err := cli.acceptLegalIfNeeded(ctx, sessionClient, *acceptTerms); err != nil {
		return err
	}
	name := *tokenName
	if name == "" {
		host, _ := os.Hostname()
		name = strings.TrimSpace("rdnsctl " + host)
	}
	// The token declares itself as the CLI, so the plan gates it as one.
	request := redundantdns.TokenCreate{
		Name: name, Scopes: splitList(*scopes), ExpiresInDays: *expiresDays, Client: redundantdns.TokenClientCLI,
	}
	minted, err := sessionClient.Tokens.Create(ctx, request)
	if redundantdns.HasCode(err, redundantdns.CodeInvalidBody) && strings.Contains(err.Error(), `"client"`) {
		// A deployment older than token clients refuses the field: mint
		// without it (the User-Agent still says rdnsctl).
		request.Client = ""
		minted, err = sessionClient.Tokens.Create(ctx, request)
	}
	if redundantdns.HasCode(err, redundantdns.CodeInvalidScope) && !flagWasSet(flags, "scopes") {
		// A deployment older than the domains module refuses its scopes:
		// mint with the ones it knows.
		request.Scopes = withoutScopes(request.Scopes, redundantdns.ScopeDomainsRead, redundantdns.ScopeDomainsWrite)
		minted, err = sessionClient.Tokens.Create(ctx, request)
	}
	if err != nil {
		return fmt.Errorf("create a personal access token: %w", err)
	}
	saved = config{
		BaseURL: baseURL, Token: minted.Token, OrgID: org.OrgID, OrgName: org.Name,
		Email: session.User.Email, TokenID: minted.Record.TokenID,
	}
	if err := saveConfig(path, saved); err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(map[string]any{"email": saved.Email, "orgId": saved.OrgID, "orgName": saved.OrgName, "tokenId": saved.TokenID, "config": path})
	}
	fmt.Fprintf(cli.stdout, "Signed in as %s, organization %s (%s).\nToken %s (%s) saved to %s.\n",
		saved.Email, org.Name, org.OrgID, minted.Record.TokenID, strings.Join(minted.Record.Scopes, ", "), path)
	return nil
}

// saveExistingToken checks a token with /v1/me and saves it.
func (cli *app) saveExistingToken(ctx context.Context, path, baseURL string, shared *globals) error {
	client, err := redundantdns.New(redundantdns.WithBaseURL(baseURL), redundantdns.WithToken(shared.token), redundantdns.WithUserAgent("rdnsctl/"+version))
	if err != nil {
		return err
	}
	me, err := client.Account.Me(ctx)
	if err != nil {
		return fmt.Errorf("check the token: %w", err)
	}
	saved := config{BaseURL: baseURL, Token: shared.token, Email: me.User.Email}
	if len(me.Orgs) > 0 {
		saved.OrgID, saved.OrgName = me.Orgs[0].OrgID, me.Orgs[0].Name
	}
	if err := saveConfig(path, saved); err != nil {
		return err
	}
	fmt.Fprintf(cli.stdout, "Token for %s, organization %s (%s), saved to %s.\n", saved.Email, saved.OrgName, saved.OrgID, path)
	return nil
}

// chooseOrg picks the organization: --org, the only one, or a prompt.
func (cli *app) chooseOrg(orgs []redundantdns.OrgSummary, wanted string) (redundantdns.OrgSummary, error) {
	if len(orgs) == 0 {
		return redundantdns.OrgSummary{}, errors.New("the account has no organization")
	}
	if wanted != "" {
		index := slices.IndexFunc(orgs, func(org redundantdns.OrgSummary) bool { return org.OrgID == wanted })
		if index < 0 {
			return redundantdns.OrgSummary{}, fmt.Errorf("you are not a member of organization %q", wanted)
		}
		return orgs[index], nil
	}
	if len(orgs) == 1 {
		return orgs[0], nil
	}
	for position, org := range orgs {
		fmt.Fprintf(cli.stderr, "  %d) %s (%s, %s)\n", position+1, org.Name, org.OrgID, org.Role)
	}
	answer, err := cli.prompt("Organization number: ")
	if err != nil {
		return redundantdns.OrgSummary{}, err
	}
	number, err := strconv.Atoi(answer)
	if err != nil || number < 1 || number > len(orgs) {
		return redundantdns.OrgSummary{}, usagef("invalid organization number %q", answer)
	}
	return orgs[number-1], nil
}

// acceptLegalIfNeeded asks for (or, with --accept-terms, records) the
// acceptance of the current Terms of Service and Privacy Policy.
func (cli *app) acceptLegalIfNeeded(ctx context.Context, sessionClient *redundantdns.Client, preaccepted bool) error {
	status, err := sessionClient.Account.Legal(ctx)
	if err != nil {
		return fmt.Errorf("read the legal status: %w", err)
	}
	if !status.Required {
		return nil
	}
	fmt.Fprintf(cli.stderr, "Using RedundantDNS requires accepting the Terms of Service (version %s, %s/terms)\nand the Privacy Policy (version %s, %s/privacy).\n",
		status.Current.Terms, sessionClient.BaseURL(), status.Current.Privacy, sessionClient.BaseURL())
	if !preaccepted {
		answer, err := cli.prompt("Do you accept them? [y/N] ")
		if err != nil {
			return err
		}
		if !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
			return errors.New("the Terms of Service and Privacy Policy were not accepted; nothing was saved")
		}
	}
	if _, err := sessionClient.Account.AcceptLegal(ctx, status.Current); err != nil {
		return fmt.Errorf("accept the legal documents: %w", err)
	}
	return nil
}

func runLogout(_ context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("logout", shared)
	positionals, err := parseArgs(flags, args)
	if err != nil {
		return err
	}
	if err := expectArgs(positionals, 0, "rdnsctl logout"); err != nil {
		return err
	}
	path, err := cli.configPath(shared)
	if err != nil {
		return err
	}
	saved, err := loadConfig(path)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	fmt.Fprintf(cli.stdout, "Removed %s.\n", path)
	if saved.TokenID != "" {
		// A token cannot revoke tokens (dashboard only).
		fmt.Fprintf(cli.stdout, "Token %s is still valid until it expires: revoke it in the dashboard (Settings, API tokens).\n", saved.TokenID)
	}
	return nil
}

func runWhoami(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("whoami", shared)
	positionals, err := parseArgs(flags, args)
	if err != nil {
		return err
	}
	if err := expectArgs(positionals, 0, "rdnsctl whoami"); err != nil {
		return err
	}
	client, err := cli.client(shared)
	if err != nil {
		return err
	}
	me, err := client.Account.Me(ctx)
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(me)
	}
	fmt.Fprintf(cli.stdout, "%s (%s, auth %s) at %s\n", me.User.Email, me.User.UserID, me.User.Kind, client.BaseURL())
	for _, org := range me.Orgs {
		fmt.Fprintf(cli.stdout, "  %s  %s  role %s  plan %s\n", org.OrgID, org.Name, org.Role, org.Plan)
	}
	return nil
}

func runVersion(_ context.Context, cli *app, _ []string) error {
	fmt.Fprintf(cli.stdout, "rdnsctl %s (go-client %s)\n", version, redundantdns.Version)
	return nil
}

// splitList splits a comma separated list, dropping empty items.
func splitList(value string) []string {
	var items []string
	for _, item := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			items = append(items, trimmed)
		}
	}
	return items
}

// withoutScopes returns scopes minus the dropped ones.
func withoutScopes(scopes []string, dropped ...string) []string {
	kept := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if !slices.Contains(dropped, scope) {
			kept = append(kept, scope)
		}
	}
	return kept
}
