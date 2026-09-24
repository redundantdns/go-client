package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	redundantdns "github.com/redundantdns/go-client"
)

// ------------------------------------------------------------ managed terms

const legalManagedUsage = `rdnsctl legal managed status
       rdnsctl legal managed accept <version>`

// cloudflareRegistrarHint explains a delegation that cannot complete
// because the domain is registered at Cloudflare Registrar.
const cloudflareRegistrarHint = `
This domain is registered at Cloudflare Registrar, which only allows
Cloudflare nameservers: the apex cannot list other providers while it is
registered there. Options:
  1. Transfer the registration to another registrar (60 days after
     registration or a previous transfer), then set the NS plan there.
  2. Subdomain redundancy: create zones such as api.<domain> here; the
     delegation is written into the parent zone and they use every provider.
  3. Keep Cloudflare as the only provider of the apex.
Guide: https://redundantdns.com/guides/cloudflare-registrar
`

// runLegalManaged shows or records the organization's acceptance of the
// Managed Provider Terms and Acceptable Use Policy.
func runLegalManaged(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("legal managed", shared)
	positionals, err := parseArgs(flags, args)
	if err != nil {
		return err
	}
	if len(positionals) == 0 || (positionals[0] != "status" && positionals[0] != "accept") {
		return usagef("usage: %s", legalManagedUsage)
	}
	client, err := cli.client(shared)
	if err != nil {
		return err
	}
	if positionals[0] == "status" {
		if len(positionals) != 1 {
			return usagef("usage: %s", legalManagedUsage)
		}
		status, err := client.Legal.ManagedStatus(ctx)
		if err != nil {
			return err
		}
		if shared.jsonOutput {
			return cli.printJSON(status)
		}
		cli.printManagedStatus(status)
		return nil
	}
	if len(positionals) != 2 {
		// Acceptance must name the version the user read.
		status, statusErr := client.Legal.ManagedStatus(ctx)
		if statusErr == nil {
			return usagef("name the version you accept: rdnsctl legal managed accept %s (text: %s)", status.Current, dash(status.URL))
		}
		return usagef("usage: %s", legalManagedUsage)
	}
	status, err := client.Legal.AcceptManaged(ctx, positionals[1])
	if err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(status)
	}
	fmt.Fprintf(cli.stdout, "Accepted the Managed Provider Terms and Acceptable Use Policy, version %s, for the organization.\n", status.Current)
	return nil
}

func (cli *app) printManagedStatus(status *redundantdns.ManagedTermsStatus) {
	fmt.Fprintf(cli.stdout, "Managed Provider Terms and Acceptable Use Policy: version %s\nText: %s\n", status.Current, dash(status.URL))
	if status.Accepted != nil {
		fmt.Fprintf(cli.stdout, "Accepted version %s on %s by %s\n", status.Accepted.Version,
			status.Accepted.AcceptedAt.UTC().Format(time.RFC3339), dash(status.Accepted.UserID))
	}
	if status.Required {
		fmt.Fprintf(cli.stdout, "Not accepted: managed providers are unavailable until an admin runs rdnsctl legal managed accept %s\n", status.Current)
	} else {
		fmt.Fprintln(cli.stdout, "Managed providers are available.")
	}
}

// refuseManagedWithoutTerms stops a managed connection without an explicit
// --accept-managed-terms, pointing at the text and the version to accept.
func (cli *app) refuseManagedWithoutTerms(ctx context.Context, client *redundantdns.Client) error {
	version, where := "<version>", "https://redundantdns.com/legal/managed-terms"
	if status, err := client.Legal.ManagedStatus(ctx); err == nil {
		version = status.Current
		if status.URL != "" {
			where = status.URL
		}
	}
	return usagef("managed providers require accepting the Managed Provider Terms and Acceptable Use Policy.\n"+
		"Read them at %s, then run the command again with --accept-managed-terms %s", where, version)
}

// ------------------------------------------------------- terraform login

const terraformLoginUsage = `rdnsctl terraform login [--base-url URL] [--file PATH] [--port N] [--no-browser] [--scopes a,b]

Signs in with OAuth on behalf of the Terraform provider: registers an OAuth
client declared as terraform-provider-redundantdns, opens the consent page
(sign in, pick the organization and scopes), then saves the tokens to the
credentials file the provider reads when it has no token (default
$XDG_CONFIG_HOME/redundantdns/terraform-oauth.json). The provider refreshes
the access token and writes the rotated refresh token back to the file.`

// defaultOAuthPort is the loopback port of the consent callback. A fixed
// port keeps the redirect URI stable, so the server hands back the same
// public client on every login.
const defaultOAuthPort = 38971

func runTerraformLogin(ctx context.Context, cli *app, args []string) error {
	shared := &globals{}
	flags := newFlagSet("terraform login", shared)
	file := flags.String("file", "", "credentials file (default $XDG_CONFIG_HOME/redundantdns/terraform-oauth.json)")
	port := flags.Int("port", defaultOAuthPort, "loopback port of the consent callback (0 = any free port)")
	noBrowser := flags.Bool("no-browser", false, "print the consent URL without opening a browser")
	scopes := flags.String("scopes", strings.Join(redundantdns.AllScopes, ","), "scopes to request, comma separated")
	positionals, err := parseArgs(flags, args)
	if err != nil {
		return err
	}
	if err := expectArgs(positionals, 0, terraformLoginUsage); err != nil {
		return err
	}
	path := *file
	if path == "" {
		base := cli.getenv("XDG_CONFIG_HOME")
		if base == "" {
			if base, err = os.UserConfigDir(); err != nil {
				return fmt.Errorf("locate the config directory: %w", err)
			}
		}
		path = redundantdns.TerraformOAuthCredentialsPath(base)
	}
	configFile, err := cli.configPath(shared)
	if err != nil {
		return err
	}
	saved, err := loadConfig(configFile)
	if err != nil {
		return err
	}
	baseURL := firstNonEmpty(shared.baseURL, cli.getenv("RDNS_BASE_URL"), saved.BaseURL, redundantdns.DefaultBaseURL)
	anonymous, err := redundantdns.New(redundantdns.WithBaseURL(baseURL), redundantdns.WithUserAgent("rdnsctl/"+version))
	if err != nil {
		return err
	}

	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		return fmt.Errorf("listen for the consent callback (try --port 0): %w", err)
	}
	defer func() { _ = listener.Close() }()
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", listener.Addr().(*net.TCPAddr).Port)

	registered, err := anonymous.OAuth.Register(ctx, redundantdns.OAuthClientRegistration{
		ClientName: "Terraform provider (rdnsctl terraform login)", RedirectURIs: []string{redirectURI},
		TokenEndpointAuthMethod: "none", Scope: strings.Join(splitList(*scopes), " "),
		SoftwareID: redundantdns.SoftwareIDTerraform, SoftwareVersion: version,
	})
	if err != nil {
		return fmt.Errorf("register the OAuth client: %w", err)
	}
	pkce, err := redundantdns.NewPKCE()
	if err != nil {
		return err
	}
	state, err := redundantdns.RandomState()
	if err != nil {
		return err
	}
	consentURL := anonymous.OAuth.AuthorizationURL(redundantdns.AuthorizationRequest{
		ClientID: registered.ClientID, RedirectURI: redirectURI, State: state,
		CodeChallenge: pkce.Challenge, Scope: strings.Join(splitList(*scopes), " "),
	})
	code, err := cli.awaitConsent(ctx, listener, consentURL, state, *noBrowser)
	if err != nil {
		return err
	}
	token, err := anonymous.OAuth.ExchangeCode(ctx, registered.ClientID, code, redirectURI, pkce.Verifier)
	if err != nil {
		return fmt.Errorf("exchange the authorization code: %w", err)
	}
	credentials := &redundantdns.OAuthCredentials{BaseURL: baseURL, ClientID: registered.ClientID, SoftwareID: redundantdns.SoftwareIDTerraform}
	credentials.Apply(token)
	client, err := redundantdns.New(redundantdns.WithBaseURL(baseURL), redundantdns.WithToken(token.AccessToken), redundantdns.WithUserAgent("rdnsctl/"+version))
	if err != nil {
		return err
	}
	me, err := client.Account.Me(ctx)
	if err != nil {
		return fmt.Errorf("check the new token: %w", err)
	}
	if len(me.Orgs) > 0 {
		credentials.OrgID = me.Orgs[0].OrgID
	}
	if err := credentials.Save(path); err != nil {
		return err
	}
	if shared.jsonOutput {
		return cli.printJSON(map[string]any{"file": path, "clientId": credentials.ClientID, "orgId": credentials.OrgID, "email": me.User.Email})
	}
	fmt.Fprintf(cli.stdout, "Terraform credentials for %s, organization %s, saved to %s.\n"+
		"The provider uses them when no token is set (or with oauth_credentials_file = %q).\n",
		me.User.Email, dash(credentials.OrgID), path, path)
	return nil
}

// awaitConsent opens (or prints) the consent URL and waits for the browser
// to come back to the loopback callback with the authorization code.
func (cli *app) awaitConsent(ctx context.Context, listener net.Listener, consentURL, state string, noBrowser bool) (string, error) {
	type outcome struct {
		code string
		err  error
	}
	results := make(chan outcome, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /callback", func(writer http.ResponseWriter, request *http.Request) {
		query := request.URL.Query()
		result := outcome{code: query.Get("code")}
		switch {
		case query.Get("state") != state:
			result = outcome{err: errors.New("the consent answer does not match this login (state mismatch)")}
		case query.Get("error") != "":
			result = outcome{err: fmt.Errorf("consent refused: %s %s", query.Get("error"), query.Get("error_description"))}
		case result.code == "":
			result = outcome{err: errors.New("the consent answer has no code")}
		}
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if result.err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintln(writer, "RedundantDNS: sign-in failed:", result.err)
		} else {
			_, _ = fmt.Fprintln(writer, "RedundantDNS: Terraform is signed in. You can close this tab.")
		}
		select {
		case results <- result:
		default:
		}
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	fmt.Fprintf(cli.stderr, "Approve Terraform's access in your browser:\n  %s\n", consentURL)
	if !noBrowser {
		open := cli.openBrowser
		if open == nil {
			open = openSystemBrowser
		}
		if err := open(consentURL); err != nil {
			fmt.Fprintln(cli.stderr, "Could not open a browser; open the URL above.")
		}
	}
	timeout := time.NewTimer(10 * time.Minute)
	defer timeout.Stop()
	select {
	case result := <-results:
		return result.code, result.err
	case <-ctx.Done():
		return "", ctx.Err()
	case <-timeout.C:
		return "", errors.New("no answer from the browser in 10 minutes")
	}
}

// openSystemBrowser opens a URL with the platform's opener.
func openSystemBrowser(target string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", target) //nolint:gosec,noctx // fixed opener, URL built by rdnsctl
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", target) //nolint:gosec,noctx // fixed opener, URL built by rdnsctl
	default:
		command = exec.Command("xdg-open", target) //nolint:gosec,noctx // fixed opener, URL built by rdnsctl
	}
	return command.Start()
}
