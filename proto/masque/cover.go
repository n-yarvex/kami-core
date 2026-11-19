package masque

import (
	"net/http"
	"strconv"
)

type coverOptions struct {
	Status  int               `json:"status"`
	Body    string            `json:"body"`
	Type    string            `json:"content_type"`
	Headers map[string]string `json:"headers"`
}

type cover struct {
	status  int
	body    []byte
	headers http.Header
}

func newCover(o coverOptions) (*cover, error) {
	c := &cover{status: o.Status, headers: http.Header{}}
	if c.status == 0 {
		c.status = http.StatusNotFound
	}
	if c.status < 200 || c.status > 599 || c.status == http.StatusSwitchingProtocols {
		return nil, errBadStatus(c.status)
	}
	if o.Body == "" && o.Status == 0 {
		o.Body = "404 page not found\n"
	}
	c.body = []byte(o.Body)
	ct := o.Type
	if ct == "" {
		ct = "text/plain; charset=utf-8"
	}
	c.headers.Set("Content-Type", ct)
	for k, v := range o.Headers {
		c.headers.Set(k, v)
	}
	c.headers.Set("Content-Length", strconv.Itoa(len(c.body)))
	return c, nil
}

type errBadStatus int

func (e errBadStatus) Error() string {
	return "masque: fallback status " + strconv.Itoa(int(e)) + " is not usable"
}

func (c *cover) serve(w http.ResponseWriter) {
	h := w.Header()
	for k, v := range c.headers {
		h[k] = v
	}
	w.WriteHeader(c.status)
	w.Write(c.body)
}
