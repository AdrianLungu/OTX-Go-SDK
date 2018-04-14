package otxapi

import (
	"net/http"
	"fmt"
)

type Indicator struct {
	Sections      []string            `json:"sections,omitempty"`
	City          interface{}         `json:"city,omitempty"`
	AreaCode      int                 `json:"area_code,omitempty"`
	PulseInfo     IndicatorPulseInfo  `json:"pulse_info,omitempty"`
	ContinentCode string              `json:"continent_code,omitempty"`
	CountryName   string              `json:"country_name,omitempty"`
	PostalCode    interface{}         `json:"postal_code,omitempty"`
	DmaCode       int                 `json:"dma_code,omitempty"`
	CountryCode   string              `json:"country_code,omitempty"`
	FlagURL       string              `json:"flag_url,omitempty"`
	Asn           string              `json:"asn,omitempty"`
	CityData      bool                `json:"city_data,omitempty"`
	Indicator     string              `json:"indicator,omitempty"`
	Whois         string              `json:"whois,omitempty"`
	TypeTitle     string              `json:"type_title,omitempty"`
	Region        interface{}         `json:"region,omitempty"`
	Charset       int                 `json:"charset,omitempty"`
	Longitude     float64             `json:"longitude,omitempty"`
	CountryCode3  string              `json:"country_code3,omitempty"`
	Reputation    int                 `json:"reputation,omitempty"`
	BaseIndicator BaseIndicator       `json:"base_indicator,omitempty"`
	Latitude      float64             `json:"latitude,omitempty"`
	Validation    IndicatorValidation `json:"validation,omitempty"`
	Type          string              `json:"type,omitempty"`
	FlagTitle     string              `json:"flag_title,omitempty"`
}

type IndicatorValidation []struct {
	Source  string `json:"source,omitempty"`
	Message string `json:"message,omitempty"`
	Name    string `json:"name,omitempty"`
}

type BaseIndicator struct {
	Indicator    string `json:"indicator,omitempty"`
	Description  string `json:"description,omitempty"`
	Title        string `json:"title,omitempty"`
	AccessReason string `json:"access_reason,omitempty"`
	AccessType   string `json:"access_type,omitempty"`
	Content      string `json:"content,omitempty"`
	Type         string `json:"type,omitempty"`
	ID           int    `json:"id,omitempty"`
}

type IndicatorPulseInfo struct {
	Count      int              `json:"count,omitempty"`
	References []interface{}    `json:"references,omitempty"`
	Pulses     []IndicatorPulse `json:"pulses,omitempty"`
}

type IndicatorTypeCounts struct {
	FileHashSHA256 int `json:"FileHash-SHA256,omitempty"`
	Domain         int `json:"domain,omitempty"`
	URL            int `json:"URL,omitempty"`
	Hostname       int `json:"hostname,omitempty"`
	Email          int `json:"email,omitempty"`
	FileHashSHA1   int `json:"FileHash-SHA1,omitempty"`
	IPv4           int `json:"IPv4,omitempty"`
	CIDR           int `json:"CIDR,omitempty"`
	CVE            int `json:"CVE,omitempty"`
	FileHashMD5    int `json:"FileHash-MD5,omitempty"`
}

type IndicatorObservation struct {
	IndicatorTypeCounts IndicatorTypeCounts `json:"indicator_type_counts,omitempty"`
	PulseSource         string              `json:"pulse_source,omitempty"`
	Description         string              `json:"description,omitempty"`
	SubscriberCount     int                 `json:"subscriber_count,omitempty"`
	ClonedFrom          interface{}         `json:"cloned_from,omitempty"`
	IsSubscribed        int                 `json:"is_subscribed,omitempty"`
	CommentCount        int                 `json:"comment_count,omitempty"`
	AuthorName          string              `json:"author_name,omitempty"`
	UpvotesCount        float64             `json:"upvotes_count,omitempty"`
	DownvotesCount      float64             `json:"downvotes_count,omitempty"`
	IsSubscribing       int                 `json:"is_subscribing,omitempty"`
	References          []interface{}       `json:"references,omitempty"`
	TargetedCountries   []interface{}       `json:"targeted_countries,omitempty"`
	Groups              []interface{}       `json:"groups,omitempty"`
	Vote                int                 `json:"vote,omitempty"`
	ValidatorCount      float64             `json:"validator_count,omitempty"`
	Adversary           string              `json:"adversary,omitempty"`
	ID                  string              `json:"id,omitempty"`
	ExtractSource       []interface{}       `json:"extract_source,omitempty"`
	Industries          []interface{}       `json:"industries,omitempty"`
	Tlp                 string              `json:"tlp,omitempty"`
	Locked              int                 `json:"locked,omitempty"`
	Name                string              `json:"name,omitempty"`
	IsFollowing         int                 `json:"is_following,omitempty"`
	Created             string              `json:"created,omitempty"`
	Tags                []interface{}       `json:"tags,omitempty"`
	Modified            string              `json:"modified,omitempty"`
	ExportCount         float64             `json:"export_count,omitempty"`
	AvatarURL           string              `json:"avatar_url,omitempty"`
	FollowerCount       float64             `json:"follower_count,omitempty"`
	VotesCount          float64             `json:"votes_count,omitempty"`
	AuthorID            int                 `json:"author_id,omitempty"`
	UserSubscriberCount float64             `json:"user_subscriber_count,omitempty"`
	Public              int                 `json:"public,omitempty"`
	Revision            int                 `json:"revision,omitempty"`
}

type IndicatorAuthor struct {
	Username     string `json:"username,omitempty"`
	IsSubscribed int    `json:"is_subscribed,omitempty"`
	AvatarURL    string `json:"avatar_url,omitempty"`
	IsFollowing  int    `json:"is_following,omitempty"`
	ID           string `json:"id,omitempty"`
}

type IndicatorPulse struct {
	IndicatorTypeCounts IndicatorTypeCounts  `json:"indicator_type_counts,omitempty"`
	PulseSource         string               `json:"pulse_source,omitempty"`
	TLP                 string               `json:"TLP,omitempty"`
	Description         string               `json:"description,omitempty"`
	SubscriberCount     int                  `json:"subscriber_count,omitempty"`
	Tags                []interface{}        `json:"tags,omitempty"`
	ExportCount         int                  `json:"export_count,omitempty"`
	IsFollowing         int                  `json:"is_following,omitempty"`
	IsModified          bool                 `json:"is_modified,omitempty"`
	UpvotesCount        float64              `json:"upvotes_count,omitempty"`
	DownvotesCount      float64              `json:"downvotes_count,omitempty"`
	ModifiedText        string               `json:"modified_text,omitempty"`
	IsSubscribing       int                  `json:"is_subscribing,omitempty"`
	References          []interface{}        `json:"references,omitempty"`
	TargetedCountries   []interface{}        `json:"targeted_countries,omitempty"`
	Groups              []interface{}        `json:"groups,omitempty"`
	Vote                int                  `json:"vote,omitempty"`
	ValidatorCount      float64              `json:"validator_count,omitempty"`
	IsAuthor            bool                 `json:"is_author,omitempty"`
	Adversary           string               `json:"adversary,omitempty"`
	ID                  string               `json:"id,omitempty"`
	Observation         IndicatorObservation `json:"observation,omitempty"`
	Industries          []interface{}        `json:"industries,omitempty"`
	Locked              int                  `json:"locked,omitempty"`
	Name                string               `json:"name,omitempty"`
	Created             string               `json:"created,omitempty"`
	ClonedFrom          interface{}          `json:"cloned_from,omitempty"`
	Modified            string               `json:"modified,omitempty"`
	CommentCount        float64              `json:"comment_count,omitempty"`
	IndicatorCount      float64              `json:"indicator_count,omitempty"`
	Author              IndicatorAuthor      `json:"author,omitempty"`
	InGroup             bool                 `json:"in_group,omitempty"`
	FollowerCount       float64              `json:"follower_count,omitempty"`
	VotesCount          float64              `json:"votes_count,omitempty"`
	Public              int                  `json:"public,omitempty"`
}

func (i Indicator) String() string {
	return Stringify(i)
}

type OTXIndicatorService struct {
	client *Client
}

func (c *OTXIndicatorService) GetIPv4(ip, section string) (*Indicator, error) {
	req, err := c.client.newRequest(http.MethodGet, fmt.Sprintf(`%s/IPv4/%s/%s`, IndicatorsURLPath, ip, section), nil)
	if err != nil {
		return nil, err
	}

	var i Indicator
	if err := c.client.do(req, &i); err != nil {
		return nil, err
	}

	return &i, nil
}
