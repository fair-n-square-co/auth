package workos

// Config holds the WorkOS settings the auth service needs. It is composed into
// the application Config (cmd/auth/config) and populated from the embedded YAML
// and AUTH_-prefixed env vars.
//
// Env var names (viper uses "_" as the key delimiter, so field names must not
// themselves contain a segment break): AUTH_WORKOS_ISSUER, AUTH_WORKOS_CLIENTID.
type Config struct {
	// Issuer is the expected WorkOS OIDC issuer. Used to validate the token `iss`
	// and locate the JWKS once signature verification lands.
	Issuer string
	// ClientID is the WorkOS client id. Reserved for signature verification
	// (audience / JWKS URL).
	ClientID string
}
