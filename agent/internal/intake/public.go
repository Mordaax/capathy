package intake

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Mordaax/capathy/agent/internal/request"
)

// Issue is the bounded GitHub issue projection. Body is untrusted data, never a tool instruction.
type Issue struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	Body   string `json:"body"`
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
	PullRequest json.RawMessage `json:"pull_request"`
}

// ParseIssues normalizes a recorded allowlisted repository response; linked attachments are never downloaded.
func ParseIssues(data []byte, repository string, allowedRepos []string) ([]request.RuleRequest, error) {
	allowed := false
	for _, repo := range allowedRepos {
		if repo == repository {
			allowed = true
		}
	}
	if !allowed || strings.Count(repository, "/") != 1 || strings.ContainsAny(repository, "?#\\ ") {
		return nil, errors.New("repository is not allowlisted")
	}
	if len(data) > 1<<20 {
		return nil, errors.New("issue response too large")
	}
	var issues []Issue
	if err := json.Unmarshal(data, &issues); err != nil {
		return nil, err
	}
	if len(issues) > 1000 {
		return nil, errors.New("issue count limit exceeded")
	}
	out := []request.RuleRequest{}
	seen := map[int]bool{}
	for _, issue := range issues {
		if issue.Number <= 0 || seen[issue.Number] || len(issue.Title) > 4096 || len(issue.Body) > 65536 {
			return nil, errors.New("invalid issue")
		}
		seen[issue.Number] = true
		if len(issue.PullRequest) > 0 {
			continue
		}
		labelled := false
		for _, label := range issue.Labels {
			if label.Name == "rule idea" {
				labelled = true
			}
		}
		if !labelled {
			continue
		}
		originURL := "https://github.com/" + repository + "/issues/" + strconv.Itoa(issue.Number)
		r := request.RuleRequest{Schema: 1, Origin: request.Origin{Kind: "issue", URL: originURL, ObservedAt: time.Now().UTC()}, Capability: issue.Title, Samples: []request.SampleRef{}, Evidence: []request.EvidenceRef{}, Sources: []string{originURL}}
		r.ID = r.Key()
		if err := r.Validate(); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// FeedItem carries public report provenance only, never payloads or local sample paths.
type FeedItem struct {
	Title     string `json:"title"`
	URL       string `json:"url"`
	Published string `json:"published,omitempty"`
}

// ParseFeed reads bounded RSS, Atom or JSON arrays with explicit link-host policy.
func ParseFeed(data []byte, sourceURL string, allowedHosts []string) ([]request.RuleRequest, error) {
	if len(data) > 1<<20 {
		return nil, errors.New("feed too large")
	}
	if _, err := publicURL(sourceURL, allowedHosts); err != nil {
		return nil, err
	}
	items := []FeedItem{}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, errors.New("empty feed")
	}
	if trimmed[0] == '[' {
		if err := json.Unmarshal(data, &items); err != nil {
			return nil, err
		}
	} else {
		decoder := xml.NewDecoder(bytes.NewReader(data))
		var current *FeedItem
		depth := 0
		for {
			token, err := decoder.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, err
			}
			switch token := token.(type) {
			case xml.StartElement:
				depth++
				if depth > 64 {
					return nil, errors.New("feed XML depth limit exceeded")
				}
				if token.Name.Local == "item" || token.Name.Local == "entry" {
					if current != nil {
						return nil, errors.New("nested feed entry")
					}
					current = &FeedItem{}
				} else if current != nil {
					switch token.Name.Local {
					case "title":
						if err = decoder.DecodeElement(&current.Title, &token); err != nil {
							return nil, err
						}
						depth--
					case "link":
						for _, attr := range token.Attr {
							if attr.Name.Local == "href" {
								current.URL = attr.Value
							}
						}
						if current.URL == "" {
							if err = decoder.DecodeElement(&current.URL, &token); err != nil {
								return nil, err
							}
							depth--
						}
					case "published", "pubDate", "updated":
						if err = decoder.DecodeElement(&current.Published, &token); err != nil {
							return nil, err
						}
						depth--
					}
				}
			case xml.EndElement:
				if (token.Name.Local == "item" || token.Name.Local == "entry") && current != nil {
					items = append(items, *current)
					current = nil
					if len(items) > 1000 {
						return nil, errors.New("feed count limit exceeded")
					}
				}
				depth--
			}
		}
	}
	if len(items) > 1000 {
		return nil, errors.New("feed count limit exceeded")
	}
	out := []request.RuleRequest{}
	seen := map[string]bool{}
	for _, item := range items {
		if item.Title == "" || len(item.Title) > 4096 || len(item.URL) > 4096 {
			return nil, errors.New("invalid feed item")
		}
		u, err := publicURL(item.URL, allowedHosts)
		if err != nil {
			return nil, err
		}
		if seen[u] {
			continue
		}
		seen[u] = true
		r := request.RuleRequest{Schema: 1, Origin: request.Origin{Kind: "feed", URL: u, ObservedAt: time.Now().UTC()}, Capability: item.Title, Sources: []string{sourceURL, u}, Samples: []request.SampleRef{}, Evidence: []request.EvidenceRef{}}
		r.ID = r.Key()
		if err = r.Validate(); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}
func publicURL(raw string, hosts []string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || u.Port() != "" || u.Fragment != "" {
		return "", errors.New("feed links require plain HTTPS URLs")
	}
	for _, host := range hosts {
		if strings.EqualFold(u.Hostname(), host) {
			return u.String(), nil
		}
	}
	return "", fmt.Errorf("feed link host is not allowlisted")
}
