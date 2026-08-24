package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"code.cloudfoundry.org/uaa-cli/version"
)

const (
	avMarker         = "@av"
	avPath           = "/usr/local/bin/av"
	avMaxBundleBytes = 1024 * 1024
)

type avToken struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type avCredentials struct {
	Targets map[string]map[string]avToken `json:"targets"`
}

var avTestEnabled bool

// EnableAVCredentialTestStore keeps upstream tests hermetic. It is
// intentionally useless unless code already executes inside this process.
func EnableAVCredentialTestStore() {
	avTestEnabled = true
	_ = os.Remove(avTestPath())
}

func hydrateAV(c *Config) error {
	marked := false
	for targetName, target := range c.Targets {
		if err := validAVKey("target", targetName); err != nil {
			return err
		}
		for contextName, context := range target.Contexts {
			if err := validAVKey("context", contextName); err != nil {
				return err
			}
			if context.Token.AccessToken == avMarker || context.Token.RefreshToken == avMarker {
				marked = true
			} else if context.Token.AccessToken != "" || context.Token.RefreshToken != "" {
				return errors.New("UAA CLI config contains plaintext OAuth tokens; run `av harden uaa-cli`")
			}
		}
	}
	if !marked {
		return nil
	}

	bundle, err := loadAV()
	if err != nil {
		return err
	}
	for targetName, target := range c.Targets {
		for contextName, context := range target.Contexts {
			stored, ok := bundle.Targets[targetName][contextName]
			if context.Token.AccessToken == avMarker {
				if !ok || stored.AccessToken == "" || stored.AccessToken == avMarker {
					return fmt.Errorf("Automic Vault has no access token for UAA target %q context %q", targetName, contextName)
				}
				context.Token.AccessToken = stored.AccessToken
			}
			if context.Token.RefreshToken == avMarker {
				if !ok || stored.RefreshToken == "" || stored.RefreshToken == avMarker {
					return fmt.Errorf("Automic Vault has no refresh token for UAA target %q context %q", targetName, contextName)
				}
				context.Token.RefreshToken = stored.RefreshToken
			}
			target.Contexts[contextName] = context
		}
		c.Targets[targetName] = target
	}
	return nil
}

func prepareAV(c Config) (Config, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return Config{}, err
	}
	var sanitized Config
	if err := json.Unmarshal(data, &sanitized); err != nil {
		return Config{}, err
	}

	bundle := avCredentials{Targets: map[string]map[string]avToken{}}
	for targetName, target := range sanitized.Targets {
		if err := validAVKey("target", targetName); err != nil {
			return Config{}, err
		}
		for contextName, context := range target.Contexts {
			if err := validAVKey("context", contextName); err != nil {
				return Config{}, err
			}
			if context.Token.AccessToken == avMarker || context.Token.RefreshToken == avMarker {
				return Config{}, errors.New("refusing to persist unresolved UAA credential markers")
			}
			if context.Token.AccessToken == "" && context.Token.RefreshToken == "" {
				continue
			}
			contexts := bundle.Targets[targetName]
			if contexts == nil {
				contexts = map[string]avToken{}
				bundle.Targets[targetName] = contexts
			}
			contexts[contextName] = avToken{
				AccessToken:  context.Token.AccessToken,
				RefreshToken: context.Token.RefreshToken,
			}
			if context.Token.AccessToken != "" {
				context.Token.AccessToken = avMarker
			}
			if context.Token.RefreshToken != "" {
				context.Token.RefreshToken = avMarker
			}
			target.Contexts[contextName] = context
		}
		sanitized.Targets[targetName] = target
	}
	if len(bundle.Targets) == 0 {
		if err := forgetAV(); err != nil {
			return Config{}, err
		}
		return sanitized, nil
	}
	if err := storeAV(bundle); err != nil {
		return Config{}, err
	}
	return sanitized, nil
}

func validAVKey(kind, value string) error {
	if value == "" || len(value) > 4096 || strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("invalid UAA %s credential key", kind)
	}
	return nil
}

func loadAV() (avCredentials, error) {
	data, err := runAV("get", nil)
	if err != nil {
		return avCredentials{}, err
	}
	var bundle avCredentials
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return avCredentials{}, fmt.Errorf("invalid UAA credential bundle from Automic Vault: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || len(bundle.Targets) == 0 {
		return avCredentials{}, errors.New("invalid UAA credential bundle from Automic Vault")
	}
	if err := validateAVCredentials(bundle); err != nil {
		return avCredentials{}, err
	}
	return bundle, nil
}

func storeAV(bundle avCredentials) error {
	if err := validateAVCredentials(bundle); err != nil {
		return err
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	if len(data) > avMaxBundleBytes {
		return errors.New("UAA credential bundle exceeds the supported size")
	}
	_, err = runAV("store", data)
	return err
}

func validateAVCredentials(bundle avCredentials) error {
	if len(bundle.Targets) == 0 || len(bundle.Targets) > 128 {
		return errors.New("invalid UAA credential bundle")
	}
	for target, contexts := range bundle.Targets {
		if validAVKey("target", target) != nil || len(contexts) == 0 || len(contexts) > 256 {
			return errors.New("invalid UAA credential bundle")
		}
		for context, token := range contexts {
			if validAVKey("context", context) != nil ||
				(token.AccessToken == "" && token.RefreshToken == "") ||
				invalidAVSecret(token.AccessToken) || invalidAVSecret(token.RefreshToken) {
				return errors.New("invalid UAA credential bundle")
			}
		}
	}
	return nil
}

func invalidAVSecret(value string) bool {
	return value == avMarker || len(value) > 512*1024 || strings.ContainsRune(value, '\x00')
}

func forgetAV() error {
	_, err := runAV("forget", nil)
	return err
}

func runAV(action string, input []byte) ([]byte, error) {
	if avTestEnabled || version.Version == "test-version" {
		switch action {
		case "get":
			return os.ReadFile(avTestPath())
		case "store":
			if err := os.MkdirAll(ConfigDir(), 0700); err != nil {
				return nil, err
			}
			return nil, os.WriteFile(avTestPath(), input, 0600)
		case "forget":
			if err := os.Remove(avTestPath()); err != nil && !os.IsNotExist(err) {
				return nil, err
			}
			return nil, nil
		default:
			return nil, errors.New("unsupported UAA credential helper action")
		}
	}
	cmd := exec.Command(avPath, "uaa-credential", action)
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("Automic Vault UAA credential helper failed: %w", err)
	}
	if len(output) > avMaxBundleBytes {
		return nil, errors.New("UAA credential bundle exceeds the supported size")
	}
	return output, nil
}

func avTestPath() string {
	return filepath.Join(ConfigDir(), ".av-test-credentials.json")
}
