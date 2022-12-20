package command

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/reloadutil"
	"github.com/hashicorp/vault/command/agent/sink/inmem"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	systemd "github.com/coreos/go-systemd/daemon"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/gatedwriter"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/agent/auth"
	"github.com/hashicorp/vault/command/agent/auth/alicloud"
	"github.com/hashicorp/vault/command/agent/auth/approle"
	"github.com/hashicorp/vault/command/agent/auth/aws"
	"github.com/hashicorp/vault/command/agent/auth/azure"
	"github.com/hashicorp/vault/command/agent/auth/cert"
	"github.com/hashicorp/vault/command/agent/auth/cf"
	"github.com/hashicorp/vault/command/agent/auth/gcp"
	"github.com/hashicorp/vault/command/agent/auth/jwt"
	"github.com/hashicorp/vault/command/agent/auth/kerberos"
	"github.com/hashicorp/vault/command/agent/auth/kubernetes"
	"github.com/hashicorp/vault/command/agent/cache"
	"github.com/hashicorp/vault/command/agent/cache/cacheboltdb"
	"github.com/hashicorp/vault/command/agent/cache/cachememdb"
	"github.com/hashicorp/vault/command/agent/cache/keymanager"
	agentConfig "github.com/hashicorp/vault/command/agent/config"
	"github.com/hashicorp/vault/command/agent/sink"
	"github.com/hashicorp/vault/command/agent/sink/file"
	"github.com/hashicorp/vault/command/agent/template"
	"github.com/hashicorp/vault/command/agent/winsvc"
	"github.com/hashicorp/vault/helper/logging"
	"github.com/hashicorp/vault/helper/metricsutil"
	"github.com/hashicorp/vault/helper/useragent"
	"github.com/hashicorp/vault/internalshared/configutil"
	"github.com/hashicorp/vault/internalshared/listenerutil"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/version"
	"github.com/kr/pretty"
	"github.com/mitchellh/cli"
	"github.com/oklog/run"
	"github.com/posener/complete"
	"google.golang.org/grpc/test/bufconn"
)

var (
	_ cli.Command             = (*AgentCommand)(nil)
	_ cli.CommandAutocomplete = (*AgentCommand)(nil)
)

const (
	// flagNameAgentExitAfterAuth is used as an Agent specific flag to indicate
	// that agent should exit after a single successful auth
	flagNameAgentExitAfterAuth = "exit-after-auth"
)

type AgentCommand struct {
	*BaseCommand
	logFlags logFlags

	ShutdownCh chan struct{}
	SighupCh   chan struct{}
	startedCh  chan (struct{}) // for tests

	// Lock and reload functions for stanza/types
	reloadFuncsLock *sync.RWMutex
	reloadFuncs     *map[string][]reloadutil.ReloadFunc

	// TODO: PW: Group these nicely...
	flagSets    *FlagSets
	agentConfig *agentConfig.Config
	// sinks       []*sink.SinkConfig
	serverInfo *serverInformation
	listeners  []net.Listener
	// TODO: PW: thinking about keeping these two separate until we need to monge them
	// for the sink server Run
	fileSinks  []*sink.SinkConfig
	inmemSinks []*sink.SinkConfig // TODO: PW: some listeners have these (not nil)

	// ....TODO: PW: add others..

	logWriter io.Writer
	logGate   *gatedwriter.Writer
	logger    log.Logger

	// Telemetry object
	metricsHelper *metricsutil.MetricsHelper

	cleanupGuard sync.Once

	flagConfigs        []string
	flagExitAfterAuth  bool
	flagTestVerifyOnly bool
}

type serverInformation struct {
	entries map[string]string
}

func NewServerInformation() *serverInformation {
	return &serverInformation{
		make(map[string]string),
	}
}

func (c *AgentCommand) Synopsis() string {
	return "Start a Vault agent"
}

func (c *AgentCommand) Help() string {
	helpText := `
Usage: vault agent [options]

  This command starts a Vault agent that can perform automatic authentication
  in certain environments.

  Start an agent with a configuration file:

      $ vault agent -config=/etc/vault/config.hcl

  For a full list of examples, please see the documentation.

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *AgentCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP)

	f := set.NewFlagSet("Command Options")

	// Augment with the log flags
	f.addLogFlags(&c.logFlags)

	f.StringSliceVar(&StringSliceVar{
		Name:   "config",
		Target: &c.flagConfigs,
		Completion: complete.PredictOr(
			complete.PredictFiles("*.hcl"),
			complete.PredictFiles("*.json"),
		),
		Usage: "Path to a configuration file. This configuration file should " +
			"contain only agent directives.",
	})

	f.BoolVar(&BoolVar{
		Name:    flagNameAgentExitAfterAuth,
		Target:  &c.flagExitAfterAuth,
		Default: false,
		Usage: "If set to true, the agent will exit with code 0 after a single " +
			"successful auth, where success means that a token was retrieved and " +
			"all sinks successfully wrote it",
	})

	// Internal-only flags to follow.
	//
	// Why hello there little source code reader! Welcome to the Vault source
	// code. The remaining options are intentionally undocumented and come with
	// no warranty or backwards-compatibility promise. Do not use these flags
	// in production. Do not build automation using these flags. Unless you are
	// developing against Vault, you should not need any of these flags.
	f.BoolVar(&BoolVar{
		Name:    "test-verify-only",
		Target:  &c.flagTestVerifyOnly,
		Default: false,
		Hidden:  true,
	})

	// End internal-only flags.

	return set
}

func (c *AgentCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *AgentCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *AgentCommand) Run(args []string) int {
	var err error

	if err := c.handleFlagSetsSetup(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	// Config flag validation
	if len(c.flagConfigs) != 1 {
		c.UI.Error("Must specify exactly one config path using -config")
		return 1
	}

	// Load the configuration file
	c.agentConfig, err = agentConfig.LoadConfig(c.flagConfigs[0])
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error loading configuration from %s: %s", c.flagConfigs[0], err))
		return 1
	}

	// Ensure at least one config was found.
	if c.agentConfig == nil {
		c.UI.Output(wrapAtLength("No configuration read. Please provide the configuration with the -config flag."))
		return 1
	}

	// TODO: Can this be moved somewhere? odd check.. one error and a warning
	if c.agentConfig.AutoAuth == nil && c.agentConfig.Cache == nil {
		c.UI.Error("No auto_auth or cache block found in config file")
		return 1
	}
	if c.agentConfig.AutoAuth == nil {
		c.UI.Info("No auto_auth block found in config file, not starting automatic authentication feature")
	}

	// TODO: PW: Update the config for flags, env vars, config file..
	// Does this actually need the flags? are we re-doing stuff?
	c.updateConfig()

	// Tests might not want to start a vault server and just want to verify the configuration.
	if c.flagTestVerifyOnly {
		if os.Getenv("VAULT_TEST_VERIFY_ONLY_DUMP_CONFIG") != "" {
			c.UI.Output(fmt.Sprintf("\nConfiguration:\n%s\n", pretty.Sprint(*c.agentConfig)))
		}
		return 0
	}

	// Logging setup
	if err := c.handleLogSetup(); err != nil {
		c.UI.Error(flattenErrors(err).Error())
		return 1
	}

	// Server info setup
	if err := c.handleServerInfoSetup(); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	// Ignore any setting of agent's address. This client is used by the agent
	// to reach out to Vault. This should never loop back to agent.
	c.flagAgentAddress = ""
	client, err := c.Client()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error fetching client: %v", err))
		return 1
	}

	// ctx and cancelFunc are passed to the AuthHandler, SinkServer, and
	// TemplateServer that periodically listen for ctx.Done() to fire and shut
	// down accordingly.
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	// telemetry configuration
	inmemMetrics, _, prometheusEnabled, err := configutil.SetupTelemetry(&configutil.SetupTelemetryOpts{
		Config:      c.agentConfig.Telemetry,
		Ui:          c.UI,
		ServiceName: "vault",
		DisplayName: "Vault",
		UserAgent:   useragent.String(),
		ClusterName: c.agentConfig.ClusterName,
	})
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error initializing telemetry: %s", err))
		return 1
	}
	c.metricsHelper = metricsutil.NewMetricsHelper(inmemMetrics, prometheusEnabled)

	var method auth.AuthMethod
	var sinks []*sink.SinkConfig
	var templateNamespace string
	if c.agentConfig.AutoAuth != nil {
		if client.Headers().Get(consts.NamespaceHeaderName) == "" && c.agentConfig.AutoAuth.Method.Namespace != "" {
			client.SetNamespace(c.agentConfig.AutoAuth.Method.Namespace)
		}
		templateNamespace = client.Headers().Get(consts.NamespaceHeaderName)

		sinkClient, err := client.CloneWithHeaders()
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error cloning client for file sink: %v", err))
			return 1
		}

		if c.agentConfig.DisableIdleConnsAutoAuth {
			sinkClient.SetMaxIdleConnections(-1)
		}

		if c.agentConfig.DisableKeepAlivesAutoAuth {
			sinkClient.SetDisableKeepAlives(true)
		}

		for _, sc := range c.agentConfig.AutoAuth.Sinks {
			switch sc.Type {
			case "file":
				config := &sink.SinkConfig{
					Logger:    c.logger.Named("sink.file"),
					Config:    sc.Config,
					Client:    sinkClient,
					WrapTTL:   sc.WrapTTL,
					DHType:    sc.DHType,
					DeriveKey: sc.DeriveKey,
					DHPath:    sc.DHPath,
					AAD:       sc.AAD,
				}
				s, err := file.NewFileSink(config)
				if err != nil {
					c.UI.Error(fmt.Errorf("Error creating file sink: %w", err).Error())
					return 1
				}
				config.Sink = s
				sinks = append(sinks, config)
			default:
				c.UI.Error(fmt.Sprintf("Unknown sink type %q", sc.Type))
				return 1
			}
		}

		authConfig := &auth.AuthConfig{
			Logger:    c.logger.Named(fmt.Sprintf("auth.%s", c.agentConfig.AutoAuth.Method.Type)),
			MountPath: c.agentConfig.AutoAuth.Method.MountPath,
			Config:    c.agentConfig.AutoAuth.Method.Config,
		}
		switch c.agentConfig.AutoAuth.Method.Type {
		case "alicloud":
			method, err = alicloud.NewAliCloudAuthMethod(authConfig)
		case "aws":
			method, err = aws.NewAWSAuthMethod(authConfig)
		case "azure":
			method, err = azure.NewAzureAuthMethod(authConfig)
		case "cert":
			method, err = cert.NewCertAuthMethod(authConfig)
		case "cf":
			method, err = cf.NewCFAuthMethod(authConfig)
		case "gcp":
			method, err = gcp.NewGCPAuthMethod(authConfig)
		case "jwt":
			method, err = jwt.NewJWTAuthMethod(authConfig)
		case "kerberos":
			method, err = kerberos.NewKerberosAuthMethod(authConfig)
		case "kubernetes":
			method, err = kubernetes.NewKubernetesAuthMethod(authConfig)
		case "approle":
			method, err = approle.NewApproleAuthMethod(authConfig)
		case "pcf": // Deprecated.
			method, err = cf.NewCFAuthMethod(authConfig)
		default:
			c.UI.Error(fmt.Sprintf("Unknown auth method %q", c.agentConfig.AutoAuth.Method.Type))
			return 1
		}
		if err != nil {
			c.UI.Error(fmt.Errorf("Error creating %s auth method: %w", c.agentConfig.AutoAuth.Method.Type, err).Error())
			return 1
		}
	}

	// We do this after auto-auth has been configured, because we don't want to
	// confuse the issue of retries for auth failures which have their own
	// config and are handled a bit differently.
	if os.Getenv(api.EnvVaultMaxRetries) == "" {
		client.SetMaxRetries(c.agentConfig.Vault.Retry.NumRetries)
	}

	enforceConsistency := cache.EnforceConsistencyNever
	whenInconsistent := cache.WhenInconsistentFail
	if c.agentConfig.APIProxy != nil {
		switch c.agentConfig.APIProxy.EnforceConsistency {
		case "always":
			enforceConsistency = cache.EnforceConsistencyAlways
		case "never", "":
		default:
			c.UI.Error(fmt.Sprintf("Unknown api_proxy setting for enforce_consistency: %q", c.agentConfig.APIProxy.EnforceConsistency))
			return 1
		}

		switch c.agentConfig.APIProxy.WhenInconsistent {
		case "retry":
			whenInconsistent = cache.WhenInconsistentRetry
		case "forward":
			whenInconsistent = cache.WhenInconsistentForward
		case "fail", "":
		default:
			c.UI.Error(fmt.Sprintf("Unknown api_proxy setting for when_inconsistent: %q", c.agentConfig.APIProxy.WhenInconsistent))
			return 1
		}
	}
	// Keep Cache configuration for legacy reasons, but error if defined alongside API Proxy
	if c.agentConfig.Cache != nil {
		switch c.agentConfig.Cache.EnforceConsistency {
		case "always":
			if enforceConsistency != cache.EnforceConsistencyNever {
				c.UI.Error("enforce_consistency configured in both api_proxy and cache blocks. Please remove this configuration from the cache block.")
				return 1
			} else {
				enforceConsistency = cache.EnforceConsistencyAlways
			}
		case "never", "":
		default:
			c.UI.Error(fmt.Sprintf("Unknown cache setting for enforce_consistency: %q", c.agentConfig.Cache.EnforceConsistency))
			return 1
		}

		switch c.agentConfig.Cache.WhenInconsistent {
		case "retry":
			if whenInconsistent != cache.WhenInconsistentFail {
				c.UI.Error("when_inconsistent configured in both api_proxy and cache blocks. Please remove this configuration from the cache block.")
				return 1
			} else {
				whenInconsistent = cache.WhenInconsistentRetry
			}
		case "forward":
			if whenInconsistent != cache.WhenInconsistentFail {
				c.UI.Error("when_inconsistent configured in both api_proxy and cache blocks. Please remove this configuration from the cache block.")
				return 1
			} else {
				whenInconsistent = cache.WhenInconsistentForward
			}
		case "fail", "":
		default:
			c.UI.Error(fmt.Sprintf("Unknown cache setting for when_inconsistent: %q", c.agentConfig.Cache.WhenInconsistent))
			return 1
		}
	}

	// Warn if cache _and_ cert auto-auth is enabled but certificates were not
	// provided in the auto_auth.method["cert"].config stanza.
	if c.agentConfig.Cache != nil && (c.agentConfig.AutoAuth != nil && c.agentConfig.AutoAuth.Method != nil && c.agentConfig.AutoAuth.Method.Type == "cert") {
		_, okCertFile := c.agentConfig.AutoAuth.Method.Config["client_cert"]
		_, okCertKey := c.agentConfig.AutoAuth.Method.Config["client_key"]

		// If neither of these exists in the cert stanza, agent will use the
		// certs from the vault stanza.
		if !okCertFile && !okCertKey {
			c.UI.Warn(wrapAtLength("WARNING! Cache is enabled and using the same certificates " +
				"from the 'cert' auto-auth method specified in the 'vault' stanza. Consider " +
				"specifying certificate information in the 'cert' auto-auth's config stanza."))
		}

	}

	// Output the header that the agent has started
	if !c.logFlags.flagCombineLogs {
		c.UI.Output("==> Vault agent started! Log data will stream in below:\n")
	}

	var leaseCache *cache.LeaseCache
	var previousToken string

	proxyClient, err := client.CloneWithHeaders()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error cloning client for proxying: %v", err))
		return 1
	}

	if c.agentConfig.DisableIdleConnsAPIProxy {
		proxyClient.SetMaxIdleConnections(-1)
	}

	if c.agentConfig.DisableKeepAlivesAPIProxy {
		proxyClient.SetDisableKeepAlives(true)
	}

	apiProxyLogger := c.logger.Named("apiproxy")

	// The API proxy to be used, if listeners are configured
	apiProxy, err := cache.NewAPIProxy(&cache.APIProxyConfig{
		Client:                 proxyClient,
		Logger:                 apiProxyLogger,
		EnforceConsistency:     enforceConsistency,
		WhenInconsistentAction: whenInconsistent,
	})
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating API proxy: %v", err))
		return 1
	}

	// Parse agent cache configurations
	if c.agentConfig.Cache != nil {
		cacheLogger := c.logger.Named("cache")

		// Create the lease cache proxier and set its underlying proxier to
		// the API proxier.
		leaseCache, err = cache.NewLeaseCache(&cache.LeaseCacheConfig{
			Client:      proxyClient,
			BaseContext: ctx,
			Proxier:     apiProxy,
			Logger:      cacheLogger.Named("leasecache"),
		})
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error creating lease cache: %v", err))
			return 1
		}

		// Configure persistent storage and add to LeaseCache
		if c.agentConfig.Cache.Persist != nil {
			if c.agentConfig.Cache.Persist.Path == "" {
				c.UI.Error("must specify persistent cache path")
				return 1
			}

			// Set AAD based on key protection type
			var aad string
			switch c.agentConfig.Cache.Persist.Type {
			case "kubernetes":
				aad, err = getServiceAccountJWT(c.agentConfig.Cache.Persist.ServiceAccountTokenFile)
				if err != nil {
					c.UI.Error(fmt.Sprintf("failed to read service account token from %s: %s", c.agentConfig.Cache.Persist.ServiceAccountTokenFile, err))
					return 1
				}
			default:
				c.UI.Error(fmt.Sprintf("persistent key protection type %q not supported", c.agentConfig.Cache.Persist.Type))
				return 1
			}

			// Check if bolt file exists already
			dbFileExists, err := cacheboltdb.DBFileExists(c.agentConfig.Cache.Persist.Path)
			if err != nil {
				c.UI.Error(fmt.Sprintf("failed to check if bolt file exists at path %s: %s", c.agentConfig.Cache.Persist.Path, err))
				return 1
			}
			if dbFileExists {
				// Open the bolt file, but wait to setup Encryption
				ps, err := cacheboltdb.NewBoltStorage(&cacheboltdb.BoltStorageConfig{
					Path:   c.agentConfig.Cache.Persist.Path,
					Logger: cacheLogger.Named("cacheboltdb"),
				})
				if err != nil {
					c.UI.Error(fmt.Sprintf("Error opening persistent cache: %v", err))
					return 1
				}

				// Get the token from bolt for retrieving the encryption key,
				// then setup encryption so that restore is possible
				token, err := ps.GetRetrievalToken()
				if err != nil {
					c.UI.Error(fmt.Sprintf("Error getting retrieval token from persistent cache: %v", err))
				}

				if err := ps.Close(); err != nil {
					c.UI.Warn(fmt.Sprintf("Failed to close persistent cache file after getting retrieval token: %s", err))
				}

				km, err := keymanager.NewPassthroughKeyManager(ctx, token)
				if err != nil {
					c.UI.Error(fmt.Sprintf("failed to configure persistence encryption for cache: %s", err))
					return 1
				}

				// Open the bolt file with the wrapper provided
				ps, err = cacheboltdb.NewBoltStorage(&cacheboltdb.BoltStorageConfig{
					Path:    c.agentConfig.Cache.Persist.Path,
					Logger:  cacheLogger.Named("cacheboltdb"),
					Wrapper: km.Wrapper(),
					AAD:     aad,
				})
				if err != nil {
					c.UI.Error(fmt.Sprintf("Error opening persistent cache with wrapper: %v", err))
					return 1
				}

				// Restore anything in the persistent cache to the memory cache
				if err := leaseCache.Restore(ctx, ps); err != nil {
					c.UI.Error(fmt.Sprintf("Error restoring in-memory cache from persisted file: %v", err))
					if c.agentConfig.Cache.Persist.ExitOnErr {
						return 1
					}
				}
				cacheLogger.Info("loaded memcache from persistent storage")

				// Check for previous auto-auth token
				oldTokenBytes, err := ps.GetAutoAuthToken(ctx)
				if err != nil {
					c.UI.Error(fmt.Sprintf("Error in fetching previous auto-auth token: %s", err))
					if c.agentConfig.Cache.Persist.ExitOnErr {
						return 1
					}
				}
				if len(oldTokenBytes) > 0 {
					oldToken, err := cachememdb.Deserialize(oldTokenBytes)
					if err != nil {
						c.UI.Error(fmt.Sprintf("Error in deserializing previous auto-auth token cache entry: %s", err))
						if c.agentConfig.Cache.Persist.ExitOnErr {
							return 1
						}
					}
					previousToken = oldToken.Token
				}

				// If keep_after_import true, set persistent storage layer in
				// leaseCache, else remove db file
				if c.agentConfig.Cache.Persist.KeepAfterImport {
					defer ps.Close()
					leaseCache.SetPersistentStorage(ps)
				} else {
					if err := ps.Close(); err != nil {
						c.UI.Warn(fmt.Sprintf("failed to close persistent cache file: %s", err))
					}
					dbFile := filepath.Join(c.agentConfig.Cache.Persist.Path, cacheboltdb.DatabaseFileName)
					if err := os.Remove(dbFile); err != nil {
						c.UI.Error(fmt.Sprintf("failed to remove persistent storage file %s: %s", dbFile, err))
						if c.agentConfig.Cache.Persist.ExitOnErr {
							return 1
						}
					}
				}
			} else {
				km, err := keymanager.NewPassthroughKeyManager(ctx, nil)
				if err != nil {
					c.UI.Error(fmt.Sprintf("failed to configure persistence encryption for cache: %s", err))
					return 1
				}
				ps, err := cacheboltdb.NewBoltStorage(&cacheboltdb.BoltStorageConfig{
					Path:    c.agentConfig.Cache.Persist.Path,
					Logger:  cacheLogger.Named("cacheboltdb"),
					Wrapper: km.Wrapper(),
					AAD:     aad,
				})
				if err != nil {
					c.UI.Error(fmt.Sprintf("Error creating persistent cache: %v", err))
					return 1
				}
				cacheLogger.Info("configured persistent storage", "path", c.agentConfig.Cache.Persist.Path)

				// Stash the key material in bolt
				token, err := km.RetrievalToken(ctx)
				if err != nil {
					c.UI.Error(fmt.Sprintf("Error getting persistent key: %s", err))
					return 1
				}
				if err := ps.StoreRetrievalToken(token); err != nil {
					c.UI.Error(fmt.Sprintf("Error setting key in persistent cache: %v", err))
					return 1
				}

				defer ps.Close()
				leaseCache.SetPersistentStorage(ps)
			}
		}
	}

	// TODO: PW: Here is the stuff..
	err = c.handleListenersSetup()
	if err != nil {
		c.UI.Error(flattenErrors(err).Error())
		return 1
	}

	// If there are templates, add an in-process listener
	if len(c.agentConfig.Templates) > 0 {
		c.agentConfig.Listeners = append(c.agentConfig.Listeners, &configutil.Listener{Type: listenerutil.BufConnType})
	}
	for i, lnConfig := range c.agentConfig.Listeners {
		var ln net.Listener
		var tlsConf *tls.Config

		if lnConfig.Type == listenerutil.BufConnType {
			inProcListener := bufconn.Listen(1024 * 1024)
			if c.agentConfig.Cache != nil {
				c.agentConfig.Cache.InProcDialer = listenerutil.NewBufConnWrapper(inProcListener)
			}
			ln = inProcListener
		} else {
			ln, tlsConf, err = cache.StartListener(lnConfig)
			if err != nil {
				c.UI.Error(fmt.Sprintf("Error starting listener: %v", err))
				return 1
			}
		}

		c.listeners = append(c.listeners, ln)

		proxyVaultToken := true
		var inmemSink sink.Sink
		if c.agentConfig.APIProxy != nil {
			if c.agentConfig.APIProxy.UseAutoAuthToken {
				apiProxyLogger.Debug("auto-auth token is allowed to be used; configuring inmem sink")
				inmemSink, err = inmem.New(&sink.SinkConfig{
					Logger: apiProxyLogger,
				}, leaseCache)
				if err != nil {
					c.UI.Error(fmt.Sprintf("Error creating inmem sink for cache: %v", err))
					return 1
				}
				sinks = append(sinks, &sink.SinkConfig{
					Logger: apiProxyLogger,
					Sink:   inmemSink,
				})
			}
			proxyVaultToken = !c.agentConfig.APIProxy.ForceAutoAuthToken
		}

		muxHandler := cache.ProxyHandler(ctx, apiProxyLogger, apiProxy, inmemSink, proxyVaultToken)

		// Parse 'require_request_header' listener config option, and wrap
		// the request handler if necessary
		if lnConfig.RequireRequestHeader && ("metrics_only" != lnConfig.Role) {
			muxHandler = verifyRequestHeader(muxHandler)
		}

		// Create a muxer and add paths relevant for the lease cache layer
		mux := http.NewServeMux()
		quitEnabled := lnConfig.AgentAPI != nil && lnConfig.AgentAPI.EnableQuit

		mux.Handle(consts.AgentPathMetrics, c.handleMetrics())
		if "metrics_only" != lnConfig.Role {
			mux.Handle(consts.AgentPathCacheClear, leaseCache.HandleCacheClear(ctx))
			mux.Handle(consts.AgentPathQuit, c.handleQuit(quitEnabled))
			mux.Handle("/", muxHandler)
		}

		scheme := "https://"
		if tlsConf == nil {
			scheme = "http://"
		}
		if ln.Addr().Network() == "unix" {
			scheme = "unix://"
		}

		// TODO: PW: can these be merged into the other map (returned)?
		infoKey := fmt.Sprintf("api address %d", i+1)
		c.serverInfo.entries[infoKey] = scheme + ln.Addr().String()

		server := &http.Server{
			Addr:              ln.Addr().String(),
			TLSConfig:         tlsConf,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			IdleTimeout:       5 * time.Minute,
			ErrorLog:          apiProxyLogger.StandardLogger(nil),
		}

		go server.Serve(ln)
	}

	// Ensure that listeners are closed at all the exits
	listenerCloseFunc := func() {
		c.handleListenerCleanup()
	}
	defer c.cleanupGuard.Do(listenerCloseFunc)

	// Inform any tests that the server is ready
	if c.startedCh != nil {
		close(c.startedCh)
	}

	var g run.Group

	// Add handling for config reload
	g.Add(func() error {
		for {
			select {
			case <-c.SighupCh:
				c.UI.Output("==> Vault Agent reload triggered")
				// TODO: PW: Do we need some kind of channel passed in to signal when it's all done?
				// TODO: PW: could use length of: reloadFuncs for buffer size since we'd expect them all to reload
				c.handleConfigReload()
			}
		}
	}, func(error) {})

	// This run group watches for signal termination
	g.Add(func() error {
		for {
			select {
			case <-c.ShutdownCh:
				c.UI.Output("==> Vault agent shutdown triggered")
				// Notify systemd that the server is shutting down
				c.notifySystemd(systemd.SdNotifyStopping)
				// Let the lease cache know this is a shutdown; no need to evict
				// everything
				if leaseCache != nil {
					leaseCache.SetShuttingDown(true)
				}
				return nil
			case <-ctx.Done():
				c.notifySystemd(systemd.SdNotifyStopping)
				return nil
			case <-winsvc.ShutdownChannel():
				return nil
			}
		}
	}, func(error) {})

	// Start auto-auth and sink servers
	if method != nil {
		enableTokenCh := len(c.agentConfig.Templates) > 0

		// Auth Handler is going to set its own retry values, so we want to
		// work on a copy of the client to not affect other subsystems.
		ahClient, err := c.client.CloneWithHeaders()
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error cloning client for auth handler: %v", err))
			return 1
		}

		if c.agentConfig.DisableIdleConnsAutoAuth {
			ahClient.SetMaxIdleConnections(-1)
		}

		if c.agentConfig.DisableKeepAlivesAutoAuth {
			ahClient.SetDisableKeepAlives(true)
		}

		ah := auth.NewAuthHandler(&auth.AuthHandlerConfig{
			Logger:                       c.logger.Named("auth.handler"),
			Client:                       ahClient,
			WrapTTL:                      c.agentConfig.AutoAuth.Method.WrapTTL,
			MinBackoff:                   c.agentConfig.AutoAuth.Method.MinBackoff,
			MaxBackoff:                   c.agentConfig.AutoAuth.Method.MaxBackoff,
			EnableReauthOnNewCredentials: c.agentConfig.AutoAuth.EnableReauthOnNewCredentials,
			EnableTemplateTokenCh:        enableTokenCh,
			Token:                        previousToken,
			ExitOnError:                  c.agentConfig.AutoAuth.Method.ExitOnError,
		})

		ss := sink.NewSinkServer(&sink.SinkServerConfig{
			Logger:        c.logger.Named("sink.server"),
			Client:        ahClient,
			ExitAfterAuth: c.agentConfig.ExitAfterAuth,
		})

		ts := template.NewServer(&template.ServerConfig{
			Logger:        c.logger.Named("template.server"),
			LogLevel:      c.logger.GetLevel(),
			LogWriter:     c.logWriter,
			AgentConfig:   c.agentConfig,
			Namespace:     templateNamespace,
			ExitAfterAuth: c.agentConfig.ExitAfterAuth,
		})

		g.Add(func() error {
			return ah.Run(ctx, method)
		}, func(error) {
			// Let the lease cache know this is a shutdown; no need to evict
			// everything
			if leaseCache != nil {
				leaseCache.SetShuttingDown(true)
			}
			cancelFunc()
		})

		g.Add(func() error {
			// var isRunning bool

			// // for select on reload chan?
			// for {
			// 	select {
			// 	case <-reloadChan:
			// 		// channel called for a reload, so we need to send that into the
			// 		// sink server so it quits and then we re-inject the new sinks and
			// 		// start it up again?
			// 		// but how do we start it the first time and carry on?

			// 		// .Run is like a blocking operation where only the context can cancel it :/
			// 	}
			// }

			// TODO: PW: this needs to be accessible elsewhere so we can get out and create
			// a new sink server to account for config changes to listeners
			sinkServerQuit := make(chan struct{})
			err := ss.Run(ctx, ah.OutputCh, sinkServerQuit, sinks)
			c.logger.Info("sinks finished, exiting")

			// Start goroutine to drain from ah.OutputCh from this point onward
			// to prevent ah.Run from being blocked.
			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					case <-ah.OutputCh:
					}
				}
			}()

			// Wait until templates are rendered
			if len(c.agentConfig.Templates) > 0 {
				<-ts.DoneCh
			}

			return err
		}, func(error) {
			// Let the lease cache know this is a shutdown; no need to evict
			// everything
			if leaseCache != nil {
				leaseCache.SetShuttingDown(true)
			}
			cancelFunc()
		})

		g.Add(func() error {
			return ts.Run(ctx, ah.TemplateTokenCh, c.agentConfig.Templates)
		}, func(error) {
			// Let the lease cache know this is a shutdown; no need to evict
			// everything
			if leaseCache != nil {
				leaseCache.SetShuttingDown(true)
			}
			cancelFunc()
			ts.Stop()
		})

	}

	// Server configuration output
	c.outputServerConfiguration(c.serverInfo)

	// Release the log gate.
	c.logGate.Flush()

	// Write out the PID to the file now that server has successfully started
	if err := c.storePidFile(c.agentConfig.PidFile); err != nil {
		c.UI.Error(fmt.Sprintf("Error storing PID: %s", err))
		return 1
	}

	// Notify systemd that the server is ready (if applicable)
	c.notifySystemd(systemd.SdNotifyReady)

	defer func() {
		if err := c.removePidFile(c.agentConfig.PidFile); err != nil {
			c.UI.Error(fmt.Sprintf("Error deleting the PID file: %s", err))
		}
	}()

	if err := g.Run(); err != nil {
		c.logger.Error("runtime error encountered", "error", err)
		c.UI.Error("Error encountered during run, refer to logs for more details.")
		return 1
	}

	return 0
}

func (c *AgentCommand) outputServerConfiguration(info *serverInformation) {
	padding := 24
	infoKeys := make([]string, 0, len(info.entries))
	for k := range info.entries {
		infoKeys = append(infoKeys, k)
	}
	sort.Strings(infoKeys)
	c.UI.Output("==> Vault agent configuration:\n")
	titleCase := cases.Title(language.AmericanEnglish)
	for _, k := range infoKeys {
		c.UI.Output(fmt.Sprintf(
			"%s%s: %s",
			strings.Repeat(" ", padding-len(k)),
			titleCase.String(k),
			info.entries[k]))
	}
	c.UI.Output("")
}

// updateConfig ensures that the config object accurately reflects the desired
// settings as configured by the user. It applies the relevant config setting based
// on the precedence (env var overrides file config, cli overrides env var).
// It mutates the config object supplied.
func (c *AgentCommand) updateConfig() error {
	if c.flagSets == nil {
		return fmt.Errorf("unable to update config, no flagsets configured")
	}
	if c.agentConfig == nil {
		return fmt.Errorf("unable to update config, no file config configured")
	}

	c.flagSets.updateLogConfig(c.agentConfig.SharedConfig)

	c.flagSets.Visit(func(fl *flag.Flag) {
		if fl.Name == flagNameAgentExitAfterAuth {
			c.agentConfig.ExitAfterAuth = c.flagExitAfterAuth
		}
	})

	c.setStringFlag(c.flagSets, c.agentConfig.Vault.Address, &StringVar{
		Name:    flagNameAddress,
		Target:  &c.flagAddress,
		Default: "https://127.0.0.1:8200",
		EnvVar:  api.EnvVaultAddress,
	})
	c.agentConfig.Vault.Address = c.flagAddress
	c.setStringFlag(c.flagSets, c.agentConfig.Vault.CACert, &StringVar{
		Name:    flagNameCACert,
		Target:  &c.flagCACert,
		Default: "",
		EnvVar:  api.EnvVaultCACert,
	})
	c.agentConfig.Vault.CACert = c.flagCACert
	c.setStringFlag(c.flagSets, c.agentConfig.Vault.CAPath, &StringVar{
		Name:    flagNameCAPath,
		Target:  &c.flagCAPath,
		Default: "",
		EnvVar:  api.EnvVaultCAPath,
	})
	c.agentConfig.Vault.CAPath = c.flagCAPath
	c.setStringFlag(c.flagSets, c.agentConfig.Vault.ClientCert, &StringVar{
		Name:    flagNameClientCert,
		Target:  &c.flagClientCert,
		Default: "",
		EnvVar:  api.EnvVaultClientCert,
	})
	c.agentConfig.Vault.ClientCert = c.flagClientCert
	c.setStringFlag(c.flagSets, c.agentConfig.Vault.ClientKey, &StringVar{
		Name:    flagNameClientKey,
		Target:  &c.flagClientKey,
		Default: "",
		EnvVar:  api.EnvVaultClientKey,
	})
	c.agentConfig.Vault.ClientKey = c.flagClientKey
	c.setBoolFlag(c.flagSets, c.agentConfig.Vault.TLSSkipVerify, &BoolVar{
		Name:    flagNameTLSSkipVerify,
		Target:  &c.flagTLSSkipVerify,
		Default: false,
		EnvVar:  api.EnvVaultSkipVerify,
	})
	c.agentConfig.Vault.TLSSkipVerify = c.flagTLSSkipVerify
	c.setStringFlag(c.flagSets, c.agentConfig.Vault.TLSServerName, &StringVar{
		Name:    flagTLSServerName,
		Target:  &c.flagTLSServerName,
		Default: "",
		EnvVar:  api.EnvVaultTLSServerName,
	})
	c.agentConfig.Vault.TLSServerName = c.flagTLSServerName

	return nil
}

func (c *AgentCommand) handleReloadLogLevel() {
	// TODO: PW: ... reload log level
}

func (c *AgentCommand) handleReloadListeners() (*serverInformation, error) {
	// TODO: PW: ... reload listeners

	var errors error

	// TODO: PW: Close the existing listeners...
	// TODO: PW: Parse and create new listeners...

	// close the old listeners
	for _, ln := range c.listeners {
		err := ln.Close()
		if err != nil {
			errors = multierror.Append(errors, err)
		}
	}

	if errors != nil {
		// TODO: Errors closing the existing listeners.
	}

	// open the newly configured ones
	return nil, nil
}

func (c *AgentCommand) handleReloadTls() {
	// TODO: PW: ... reload TLS/certs
	// TODO: PW: better name? handleReloadCerts ?
}

func (c *AgentCommand) handleConfigReload() {
	// Let's just do one reload at a time
	c.reloadFuncsLock.Lock()
	defer c.reloadFuncsLock.Unlock()

	// Notify systemd that Agent is reloading (and then has reloaded)
	c.notifySystemd(systemd.SdNotifyReloading)
	defer c.notifySystemd(systemd.SdNotifyReady)

	// TODO: PW: Reload the supported 'reloadable' parts of config.
	// Load the config file
	// Merge the new config file with the existing config to 'update' it
	// Now we need to clean up or reset:
	// LOG LEVEL
	// LISTENERS
	// TLS CONFIG
	// ... do we need some kind of errgroup/waitgroup to task.whenall the things?
}

// verifyRequestHeader wraps an http.Handler inside a Handler that checks for
// the request header that is used for SSRF protection.
func verifyRequestHeader(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if val, ok := r.Header[consts.RequestHeaderName]; !ok || len(val) != 1 || val[0] != "true" {
			logical.RespondError(w,
				http.StatusPreconditionFailed,
				fmt.Errorf("missing %q header", consts.RequestHeaderName))
			return
		}

		handler.ServeHTTP(w, r)
	})
}

func (c *AgentCommand) notifySystemd(status string) {
	sent, err := systemd.SdNotify(false, status)
	if err != nil {
		c.logger.Error("error notifying systemd", "error", err)
	} else {
		if sent {
			c.logger.Debug("sent systemd notification", "notification", status)
		} else {
			c.logger.Debug("would have sent systemd notification (systemd not present)", "notification", status)
		}
	}
}

func (c *AgentCommand) setStringFlag(f *FlagSets, configVal string, fVar *StringVar) {
	var isFlagSet bool
	f.Visit(func(f *flag.Flag) {
		if f.Name == fVar.Name {
			isFlagSet = true
		}
	})

	flagEnvValue, flagEnvSet := os.LookupEnv(fVar.EnvVar)
	switch {
	case isFlagSet:
		// Don't do anything as the flag is already set from the command line
	case flagEnvSet:
		// Use value from env var
		*fVar.Target = flagEnvValue
	case configVal != "":
		// Use value from config
		*fVar.Target = configVal
	default:
		// Use the default value
		*fVar.Target = fVar.Default
	}
}

func (c *AgentCommand) setBoolFlag(f *FlagSets, configVal bool, fVar *BoolVar) {
	var isFlagSet bool
	f.Visit(func(f *flag.Flag) {
		if f.Name == fVar.Name {
			isFlagSet = true
		}
	})

	flagEnvValue, flagEnvSet := os.LookupEnv(fVar.EnvVar)
	switch {
	case isFlagSet:
		// Don't do anything as the flag is already set from the command line
	case flagEnvSet:
		// Use value from env var
		*fVar.Target = flagEnvValue != ""
	case configVal:
		// Use value from config
		*fVar.Target = configVal
	default:
		// Use the default value
		*fVar.Target = fVar.Default
	}
}

// storePidFile is used to write out our PID to a file if necessary
func (c *AgentCommand) storePidFile(pidPath string) error {
	// Quit fast if no pidfile
	if pidPath == "" {
		return nil
	}

	// Open the PID file
	pidFile, err := os.OpenFile(pidPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("could not open pid file: %w", err)
	}
	defer pidFile.Close()

	// Write out the PID
	pid := os.Getpid()
	_, err = pidFile.WriteString(fmt.Sprintf("%d", pid))
	if err != nil {
		return fmt.Errorf("could not write to pid file: %w", err)
	}
	return nil
}

// removePidFile is used to cleanup the PID file if necessary
func (c *AgentCommand) removePidFile(pidPath string) error {
	if pidPath == "" {
		return nil
	}
	return os.Remove(pidPath)
}

// GetServiceAccountJWT reads the service account jwt from `tokenFile`. Default is
// the default service account file path in kubernetes.
func getServiceAccountJWT(tokenFile string) (string, error) {
	if len(tokenFile) == 0 {
		tokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	}
	token, err := ioutil.ReadFile(tokenFile)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(token)), nil
}

func (c *AgentCommand) handleMetrics() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			logical.RespondError(w, http.StatusMethodNotAllowed, nil)
			return
		}

		if err := r.ParseForm(); err != nil {
			logical.RespondError(w, http.StatusBadRequest, err)
			return
		}

		format := r.Form.Get("format")
		if format == "" {
			format = metricsutil.FormatFromRequest(&logical.Request{
				Headers: r.Header,
			})
		}

		resp := c.metricsHelper.ResponseForFormat(format)

		status := resp.Data[logical.HTTPStatusCode].(int)
		w.Header().Set("Content-Type", resp.Data[logical.HTTPContentType].(string))
		switch v := resp.Data[logical.HTTPRawBody].(type) {
		case string:
			w.WriteHeader((status))
			w.Write([]byte(v))
		case []byte:
			w.WriteHeader(status)
			w.Write(v)
		default:
			logical.RespondError(w, http.StatusInternalServerError, fmt.Errorf("wrong response returned"))
		}
	})
}

func (c *AgentCommand) handleQuit(enabled bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !enabled {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.Method {
		case http.MethodPost:
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		c.logger.Debug("received quit request")
		close(c.ShutdownCh)
	})
}

// newLogConfig parses values stored in the AgentConfig to produce a LogConfig
// which can be used to configure a logger. If there are problems parsing values
// errors will be returned for all issues as a multierror.
func newLogConfig(config *agentConfig.Config) (*logging.LogConfig, error) {
	var errors error

	// Parse all the log related config
	logLevel, err := logging.ParseLogLevel(config.LogLevel)
	if err != nil {
		errors = multierror.Append(errors, err)
	}

	logFormat, err := logging.ParseLogFormat(config.LogFormat)
	if err != nil {
		errors = multierror.Append(errors, err)
	}

	logRotateDuration, err := parseutil.ParseDurationSecond(config.LogRotateDuration)
	if err != nil {
		errors = multierror.Append(errors, err)
	}

	logRotateBytes, err := parseutil.SafeParseInt(config.LogRotateBytes)
	if err != nil {
		errors = multierror.Append(errors, err)
	}

	logRotateMaxFiles, err := parseutil.SafeParseInt(config.LogRotateMaxFiles)
	if err != nil {
		errors = multierror.Append(errors, err)
	}

	if errors != nil {
		return nil, errors
	}

	logCfg := &logging.LogConfig{
		Name:              "vault-agent",
		LogLevel:          logLevel,
		LogFormat:         logFormat,
		LogFilePath:       config.LogFile,
		LogRotateDuration: logRotateDuration,
		LogRotateBytes:    logRotateBytes,
		LogRotateMaxFiles: logRotateMaxFiles,
	}

	return logCfg, nil
}

func (c *AgentCommand) updateLogLevel(logCfg *logging.LogConfig) error {
	if c.logger == nil {
		return fmt.Errorf("cannot update log level, no logger configured")
	}

	c.logger.SetLevel(logCfg.LogLevel)
	return nil
}

// handleFlagSetsSetup handles the parsing of the command line args and assignment of them
// to both the flagsets but also the flagsets to be stored against the AgentCommand struct.
func (c *AgentCommand) handleFlagSetsSetup(args []string) error {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		return err
	}

	c.flagSets = f
	return nil
}

// handleLogSetup handles parsing loaded file config into log config, it sets up and
// assigns the logger to the AgentCommand struct.
func (c *AgentCommand) handleLogSetup() error {
	// Sanity check things we need to set up logs.
	if c.agentConfig == nil {
		return fmt.Errorf("cannot configure logging, agent config not yet parsed")
	}

	// Create a logger.
	// We wrap it in a gated writer so that it doesn't start logging too early.
	if c.logGate == nil {
		c.logGate = gatedwriter.NewWriter(os.Stderr)
	}
	if c.logWriter == nil {
		c.logWriter = c.logGate
	}

	if c.logFlags.flagCombineLogs {
		c.logWriter = os.Stdout
	}

	logCfg, err := newLogConfig(c.agentConfig)
	if err != nil {
		return err
	}

	logger, err := logging.Setup(logCfg, c.logWriter)
	if err != nil {
		return err
	}

	c.logger = logger
	return nil
}

// handleListenerCleanup attemps to close all registered listeners
// any errors from closing are returned to the caller in a multierror.
func (c *AgentCommand) handleListenerCleanup() error {
	if c.listeners == nil {
		return nil
	}

	var errors error
	// TODO: PW: Should we bother tracking ones that failed to close?
	// or just blast them at the end?? feels like extra complication
	// var badListeners []net.Listener

	// Try and close any existing listeners before configuring
	for _, ln := range c.listeners {
		err := ln.Close()
		if err != nil {
			errors = multierror.Append(errors, err)
			// badListeners = append(badListeners, ln)
		}
	}

	if errors != nil {
		// Leave the bad listeners in case of a retry??
		// c.listeners = badListeners
		return errors
	}

	c.listeners = nil
	return nil
}

func (c *AgentCommand) handleListenersSetup(ctx context.Context, leaseCache *cache.LeaseCache, apiProxy *cache.Proxier) error {
	// Sanity check
	if c.agentConfig == nil {
		return fmt.Errorf("cannot configure listeners, agent config not parsed")
	}

	if c.agentConfig.Listeners == nil {
		return fmt.Errorf("cannot configure listeners, no listeners parsed from config")
	}

	var errors error

	// TODO: PW: We might need to close/remove/etc the other stuff that's wired to a listener, sink.. server info will
	// have to be blasted and reloaded from scratch as it's unconnected at this point

	// Try and close any existing listeners before configuring
	errors = c.handleListenerCleanup()
	if errors != nil {
		return errors
	}

	// If there are templates, add an in-process listener as part of config
	if len(c.agentConfig.Templates) > 0 {
		c.agentConfig.Listeners = append(c.agentConfig.Listeners, &configutil.Listener{Type: listenerutil.BufConnType})
	}

	for i, lnConfig := range c.agentConfig.Listeners {
		var ln net.Listener
		var tlsConf *tls.Config
		var err error

		// TODO: PW: I don't understand what the intention of this is, but weirdly it fiddled with:
		// c.agentConfig.Cache.InProcDialer which feels odd, we're changing config we parsed from the user
		// https://github.com/hashicorp/vault/blob/main/command/agent.go#L713
		if lnConfig.Type == listenerutil.BufConnType {
			inProcListener := bufconn.Listen(1024 * 1024)
			if c.agentConfig.Cache != nil {
				c.agentConfig.Cache.InProcDialer = listenerutil.NewBufConnWrapper(inProcListener)
			}
			ln = inProcListener
		} else {
			ln, tlsConf, err = cache.StartListener(lnConfig)
			if err != nil {
				return err
			}
		}

		// TODO: why add the listener at this point, there's loads of stuff it is used for
		// before we should 'add' it to the list of registered listeners.
		// the docs say a listener is: How Vault listens for API requests.
		// that sounds like a mistake? aren't we saying: how Vault Agent listens for API requests?
		c.listeners = append(c.listeners, ln)

		// listeners can be configured with proxy related settings
		// https://developer.hashicorp.com/vault/docs/configuration/listener/tcp#proxy_protocol_behavior
		// so the handler used by the mux (router) needs to be a proxy one.

		proxyCfg := &cache.ProxyHandlerConfig{
			Logger:  nil,
			Proxier: apiProxy,
			// Sink:                  &inmemSink,
			ShouldProxyVaultToken: true,
		}

		// var inmemSink sink.Sink
		if c.agentConfig.APIProxy != nil {
			proxyCfg.ShouldProxyVaultToken = !c.agentConfig.APIProxy.ForceAutoAuthToken
		}

		if c.agentConfig.APIProxy != nil && c.agentConfig.APIProxy.UseAutoAuthToken {
			proxyCfg.Logger.Debug("auto-auth token is allowed to be used; configuring inmem sink")

			s, err := inmem.New(&sink.SinkConfig{
				Logger: proxyCfg.Logger,
			}, leaseCache)
			if err != nil {
				return err
			}
			proxyCfg.Sink = s

			// TODO: PW: We're adding to this, how is it tracked in relation to the handler in case we reload??
			// we'd need to remove this sink from the slice, as the length of the slice is tracked in the sink server
			// to see when it needs to ignore stuff...
			sinks = append(sinks, &sink.SinkConfig{
				Logger: proxyCfg.Logger,
				Sink:   proxyCfg.Sink,
			})
		}

		muxHandler := cache.ProxyHandler2(ctx, proxyCfg)

		// Basically this little if then wrap the func thing is just adding a
		// check for 'X-Vault-Request' on the req....

		// Parse 'require_request_header' listener config option, and wrap
		// the request handler if necessary
		if lnConfig.RequireRequestHeader && ("metrics_only" != lnConfig.Role) {
			muxHandler = verifyRequestHeader(muxHandler)
		}

		// Create a muxer and add paths relevant for the lease cache layer
		mux := http.NewServeMux()
		quitEnabled := lnConfig.AgentAPI != nil && lnConfig.AgentAPI.EnableQuit

		mux.Handle(consts.AgentPathMetrics, c.handleMetrics())
		if "metrics_only" != lnConfig.Role {
			mux.Handle(consts.AgentPathCacheClear, leaseCache.HandleCacheClear(ctx))
			mux.Handle(consts.AgentPathQuit, c.handleQuit(quitEnabled))
			mux.Handle("/", muxHandler)
		}

		scheme := "https://"
		if tlsConf == nil {
			scheme = "http://"
		}
		if ln.Addr().Network() == "unix" {
			scheme = "unix://"
		}

		// TODO: PW: can these be merged into the other map (returned)?
		infoKey := fmt.Sprintf("api address %d", i+1)
		c.serverInfo.entries[infoKey] = scheme + ln.Addr().String()

		server := &http.Server{
			Addr:              ln.Addr().String(),
			TLSConfig:         tlsConf,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			IdleTimeout:       5 * time.Minute,
			ErrorLog:          apiProxyLogger.StandardLogger(nil),
		}

		go server.Serve(ln)
	}
}

func (c *AgentCommand) getMuxFoo() (*http.ServeMux, error) {
}

func (c *AgentCommand) handleServerInfoSetup() error {
	// Sanity check
	if c.logger == nil {
		return fmt.Errorf("cannot configure server information, no logger configured")
	}

	c.serverInfo = NewServerInformation()
	c.serverInfo.entries["log level"] = c.logger.GetLevel().String()

	if version.CgoEnabled {
		c.serverInfo.entries["cgo"] = "enabled"
	} else {
		c.serverInfo.entries["cgo"] = "disabled"
	}

	verInfo := version.GetVersion()
	c.serverInfo.entries["version"] = verInfo.FullVersionNumber(false)

	if verInfo.Revision != "" {
		c.serverInfo.entries["version sha"] = strings.Trim(verInfo.Revision, "'")
	}

	return nil
}

// flattenErrors will accept an error which may or may not be a multierror, it
// will flatten multierrors when present and return a single error .
func flattenErrors(errors error) error {
	if merr, ok := errors.(*multierror.Error); ok {
		return multierror.Flatten(merr)
	} else {
		return errors
	}
}
