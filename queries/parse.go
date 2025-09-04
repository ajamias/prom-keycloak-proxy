package queries

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

const (
	QueryParam    = "query"
	MatchersParam = "match[]"
)

func ParseQuery(query string) (ms []*labels.Matcher, err error) {
	m, err := parser.ParseMetricSelector(query)
	return m, err
}

func LabelValuesToRegexpString(labelValues []string) string {
	lvs := make([]string, len(labelValues))
	for i := range labelValues {
		lvs[i] = regexp.QuoteMeta(labelValues[i])
	}

	return strings.Join(lvs, "|")
}
func MatchersToString(ms ...*labels.Matcher) string {
	var el []string
	for _, m := range ms {
		el = append(el, m.String())
	}
	return fmt.Sprintf("{%v}", strings.Join(el, ","))
}

func InjectMatcher(q url.Values, matcher *labels.Matcher) error {
	matchers := q[QueryParam]
	if len(matchers) == 0 {
		q.Set(QueryParam, MatchersToString(matcher))
		return nil
	}

	// Inject label into existing matchers.
	for i, m := range matchers {
		ms, err := parser.ParseMetricSelector(m)
		if err != nil {
			return err
		}

		matchers[i] = MatchersToString(append(ms, matcher)...)
	}
	q[QueryParam] = matchers

	return nil
}

func AppendMatcher(queryValues url.Values, queryValuesForAuth url.Values, key string, authKey string, defaultValue string) (string, labels.MatchType, error) {
	value := defaultValue
	matchType := labels.MatchEqual
	expr, exprErr := parser.ParseExpr(queryValues[QueryParam][0])
	matchers := parser.ExtractSelectors(expr)
	if exprErr != nil {
		log.Panic(exprErr)
	}
	for _, matcherSelector := range matchers {
		for _, matcherSelector := range matcherSelector {
			if matcherSelector.Name == key {
				value = matcherSelector.Value
				matchType = matcherSelector.Type
			}
		}
	}

	if value != "" {
		matcher := &labels.Matcher{
			Name:  authKey,
			Type:  matchType,
			Value: LabelValuesToRegexpString([]string{value}),
		}
		err := InjectMatcher(queryValuesForAuth, matcher)
		return value, matchType, err
	}
	return value, matchType, nil
}

func findMatcherFromName(matchers []*labels.Matcher, name string) (*labels.Matcher) {
	matcherIndex := slices.IndexFunc(matchers, func(m *labels.Matcher) (bool) {
		return m.Name == name
	})
	if matcherIndex == -1 {
		return nil
	}
	return matchers[matcherIndex]
}

func ParseAuthorizations(hubKey string, clusterKey string, projectKey string, hub string, matchers []*labels.Matcher) (string) {
	resourceName := fmt.Sprintf("%s-%s", hubKey, hub)

	matcher := findMatcherFromName(matchers, "cluster")
	if matcher.Value != "" {
		if matcher.Type == labels.MatchRegexp {
			resourceName = fmt.Sprintf("%s-%s-(%s)", resourceName, clusterKey, matcher.Value)
		} else {
			resourceName = fmt.Sprintf("%s-%s-%s", resourceName, clusterKey, matcher.Value)
		}

		exportedNamespaceMatcher := findMatcherFromName(matchers, "exported_namespace")
		namespaceMatcher := findMatcherFromName(matchers, "namespace")
		if exportedNamespaceMatcher == nil && namespaceMatcher == nil {
			return resourceName
		}

		exportedNamespaceValue := "$^"
		if exportedNamespaceMatcher != nil && exportedNamespaceMatcher.Value != "" {
			if exportedNamespaceMatcher.Type == labels.MatchEqual {
				exportedNamespaceValue = regexp.QuoteMeta(exportedNamespaceMatcher.Value)
			} else {
				exportedNamespaceValue = exportedNamespaceMatcher.Value
			}
		}

		namespaceValue := "$^"
		if namespaceMatcher != nil && namespaceMatcher.Value != "" {
			if namespaceMatcher.Type == labels.MatchEqual {
				namespaceValue = regexp.QuoteMeta(namespaceMatcher.Value)
			} else {
				namespaceValue = namespaceMatcher.Value
			}
		}

		resourceName = fmt.Sprintf("%s-%s-(%s|%s)$", resourceName, projectKey, exportedNamespaceValue, namespaceValue)
	}

	return resourceName
}

func PromqlQueryFromResourceNames(metric string, resourceNames []string, hubKey string, clusterKey string, projectKey string) (string) {
	clusters := make([]*string, len(resourceNames))
	namespaces := make([]*string, len(resourceNames))

	for i, _ := range resourceNames {
		clusters[i] = nil
		namespaces[i] = nil

		re := regexp.MustCompile(fmt.Sprintf("^%s-([\\w-]+)-%s-([\\w-]+)-%s-([\\w-]+)$", hubKey, clusterKey, projectKey))
		if matches := re.FindStringSubmatch(resourceNames[i]); matches != nil {
			clusters[i] = &matches[2]
			namespaces[i] = &matches[3]
			continue
		}

		re = regexp.MustCompile(fmt.Sprintf("^%s-([\\w-]+)-%s-([\\w-]+)$", hubKey, clusterKey))
		if matches := re.FindStringSubmatch(resourceNames[i]); matches != nil {
			clusters[i] = &matches[2]
			continue
		}
	}

	queries := make([]string, len(resourceNames))
	for i := 0; i < len(resourceNames); i++ {
		if clusters[i] != nil && namespaces != nil {
			queries[i] = fmt.Sprintf("%s{cluster=\"%s\",namespace=\"%s\"}", metric, *clusters[i], *namespaces[i])
		} else if clusters[i] != nil {
			queries[i] = fmt.Sprintf("%s{cluster=\"%s\"}", metric, *clusters[i])
		} else if namespaces[i] != nil {
			queries[i] = fmt.Sprintf("%s{namespace=\"%s\"}", metric, *namespaces[i])
		} else {
			queries[i] = metric
		}
	}

	return strings.Join(queries, " or ")
}

func QueryPrometheus(prometheusTlsCertPath string, prometheusTlsKeyPath string,
	prometheusCaCertPath string, prometheusUrl string) (interface{}, error) {
	prometheusCaCert, err := os.ReadFile(prometheusCaCertPath)
	if err != nil {
		log.Panic(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(prometheusCaCert)
	cert, err := tls.LoadX509KeyPair(prometheusTlsCertPath, prometheusTlsKeyPath)
	if err != nil {
		log.Panic(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}

	response, err := client.Get(prometheusUrl)
	if err == nil {
		defer response.Body.Close() //nolint:errcheck
		var data interface{}
		json.NewDecoder(response.Body).Decode(&data) //nolint:errcheck
		return data, err
	} else {
		return nil, err
	}
}
