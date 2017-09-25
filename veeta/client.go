package veeta

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/pyama86/vaz/scan"
)

const VEETAToken = "VEETA-TOKEN"

type Client struct {
	Endpoint string
	Token    string
}

type Host struct {
	HostID     string
	Name       string
	ScanResult scan.ScanResult
	Service    Service
	Alerts     scan.Alerts
}

type Service struct {
	Name string
}

func NewClient(endpoint, token string) *Client {
	return &Client{
		Endpoint: endpoint,
		Token:    token,
	}
}

func (c Client) requestHost(host *Host, url, rtype string) error {
	j, err := json.Marshal(&host)
	if err != nil {
		return err
	}
	h, err := c.request(j, url, rtype)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(h, &host); err != nil {
		return err
	}
	return nil
}

func (c Client) CreateHost(host *Host) error {
	url := fmt.Sprintf("%s/hosts", c.Endpoint)
	return c.requestHost(host, url, "POST")
}

func (c Client) UpdateHost(host *Host) error {
	url := fmt.Sprintf("%s/hosts/%s", c.Endpoint, host.HostID)
	return c.requestHost(host, url, "PUT")
}

func (c Client) request(body []byte, url, rtype string) ([]byte, error) {

	req, err := http.NewRequest(rtype, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(VEETAToken, c.Token)
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusOK {
		message := ""
		switch res.StatusCode {
		case http.StatusTooManyRequests:
			message = "Rate limit reached"
		default:
			b, err := ioutil.ReadAll(res.Body)
			if err != nil {
				return nil, err
			}
			message = string(b)
		}
		return nil, errors.New(message)
	}

	bufbody := new(bytes.Buffer)
	if _, err := bufbody.ReadFrom(res.Body); err != nil {
		return nil, err
	}
	return bufbody.Bytes(), nil
}
