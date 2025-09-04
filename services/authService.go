// Thanks to okemechris on GitHub for the sample code.
// See: https://github.com/okemechris/simplego-api/tree/main

package services

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/OCP-on-NERC/prom-keycloak-proxy/errors"
	"github.com/OCP-on-NERC/prom-keycloak-proxy/queries"

	"github.com/prometheus/prometheus/promql/parser"

	"github.com/Nerzal/gocloak/v13"
	_ "github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

type LoginResponse struct {
	AccessToken string `json:"access_token"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
}

func InitializeOauthServer(authBaseUrl string, authTlsVerify bool) *gocloak.GoCloak {
	client := gocloak.NewClient(authBaseUrl)
	if !authTlsVerify {
		restyClient := client.RestyClient()
		restyClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: !authTlsVerify})
	}
	return client
}

func Protect(hubKey string, clusterKey string, projectKey string, gocloakClient *gocloak.GoCloak, authRealm string, authClientId string, authClientSecret string, proxyAcmHub string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get(queries.QueryParam)

		authHeader := r.Header.Get("Authorization")

		if len(authHeader) < 1 {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(errors.UnauthorizedError()) //nolint:errcheck
			return
		}

		accessToken := strings.Split(authHeader, " ")[1]

		rptResult, err := gocloakClient.RetrospectToken(r.Context(), accessToken, authClientId, authClientSecret, authRealm)

		if err != nil {
			log.Warn().
				Int("status", 401).
				Str("method", r.Method).
				Str("path", r.RequestURI).
				Str("ip", r.RemoteAddr).
				Str("client-id", authClientId).
				Str("query", query).
				Msg("Unauthorized")

			w.WriteHeader(401)
			json.NewEncoder(w).Encode(errors.BadRequestError(err.Error())) //nolint:errcheck
			return
		}

		userInfo, err := gocloakClient.GetUserInfo(context.Background(), accessToken, authRealm)
		if err != nil {
			log.Warn().
				Int("status", 401).
				Str("method", r.Method).
				Str("path", r.RequestURI).
				Str("ip", r.RemoteAddr).
				Str("client-id", authClientId).
				Str("query", query).
				Msg("Unauthorized")

			w.WriteHeader(401)
			json.NewEncoder(w).Encode(errors.BadRequestError(err.Error())) //nolint:errcheck
			return
		}

		username := *userInfo.PreferredUsername
		var userClientId = ""
		if strings.Contains(username, "service-account-") {
			userClientId = strings.ReplaceAll(username, "service-account-", "")
		}

		isTokenValid := *rptResult.Active
		if !isTokenValid {
			log.Warn().
				Int("status", 401).
				Str("method", r.Method).
				Str("path", r.RequestURI).
				Str("ip", r.RemoteAddr).
				Str("username", username).
				Str("client-id", userClientId).
				Str("query", query).
				Msg("Unauthorized")

			w.WriteHeader(401)
			json.NewEncoder(w).Encode(errors.UnauthorizedError()) //nolint:errcheck
			return
		}

		queryValues := r.URL.Query()
		matchers, err := parser.ParseMetricSelector(r.URL.Query()["query"][0])
		if err != nil {
			log.Panic()
		}
		resourceName := queries.ParseAuthorizations(hubKey, clusterKey, projectKey, proxyAcmHub, matchers)
		re, err := regexp.Compile(resourceName)
		if err != nil {
			log.Warn().
				Int("status", 400).
				Str("method", r.Method).
				Str("path", r.RequestURI).
				Str("ip", r.RemoteAddr).
				Str("username", username).
				Str("client-id", userClientId).
				Str("query", query).
				Msg("Bad Request")

			w.WriteHeader(400)
			json.NewEncoder(w).Encode(errors.BadRequestError(err.Error()))
			return
		}

		rpp, err := gocloakClient.GetRequestingPartyPermissions(
			context.Background(),
			accessToken,
			authRealm,
			gocloak.RequestingPartyTokenOptions{
				Audience:    gocloak.StringP(authClientId),
			},
		)
		if err != nil {
			log.Warn().
				Int("status", 403).
				Str("method", r.Method).
				Str("path", r.RequestURI).
				Str("ip", r.RemoteAddr).
				Str("username", username).
				Str("client-id", userClientId).
				Str("query", query).
				Msg(err.Error())

			w.WriteHeader(403)
			json.NewEncoder(w).Encode(errors.UnauthorizedError()) //nolint:errcheck
			return
		}

		out, err := json.Marshal(*rpp)
		if err != nil {
			log.Warn().
				Int("status", 400).
				Str("method", r.Method).
				Str("path", r.RequestURI).
				Str("ip", r.RemoteAddr).
				Str("username", username).
				Str("client-id", userClientId).
				Str("query", query).
				Msg("Bad Request")

			w.WriteHeader(400)
			json.NewEncoder(w).Encode(errors.BadRequestError(err.Error())) //nolint:errcheck
			return
		}

		// for all permissions associated with the token, if it matches the regex, add it to URL.values
		// get a label.matcher from a ResourceName
		var metricName string
		for _, matcher := range matchers {
			if matcher.Name == "__name__" {
				metricName = matcher.Value
				break
			}
		}
		var authorizedResourceNames []string
		for _, permission := range *rpp {
			if slices.Contains(*permission.Scopes, "GET") && re.MatchString(*permission.ResourceName) {
				authorizedResourceNames = append(authorizedResourceNames, *permission.ResourceName)
			}
		}

		newQuery := queries.PromqlQueryFromResourceNames(metricName, authorizedResourceNames, hubKey, clusterKey, projectKey)
		queryValues.Set("query", newQuery)
		r.URL.RawQuery = queryValues.Encode()

		log.Info().
			Int("status", 200).
			Str("method", r.Method).
			Str("path", r.RequestURI).
			Str("ip", r.RemoteAddr).
			Str("username", username).
			Str("client-id", userClientId).
			Str("query", query).
			RawJSON("permissions", out).
			Msg("OK")

		// Our middleware logic goes here...
		next.ServeHTTP(w, r)
	})
}
