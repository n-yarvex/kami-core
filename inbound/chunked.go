package inbound

import (
	"fmt"
	"io"
)

type chunked struct{ w io.Writer }

func newChunked(w io.Writer) *chunked { return &chunked{w: w} }

func (c *chunked) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if _, err := fmt.Fprintf(c.w, "%x\r\n", len(p)); err != nil {
		return 0, err
	}
	n, err := c.w.Write(p)
	if err != nil {
		return n, err
	}
	_, err = io.WriteString(c.w, "\r\n")
	return n, err
}

func (c *chunked) Close() error {
	_, err := io.WriteString(c.w, "0\r\n\r\n")
	return err
}
