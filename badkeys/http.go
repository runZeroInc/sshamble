package badkeys

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

func httpGet(url string, timeout time.Duration) (*http.Response, context.CancelFunc, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		_, dummyCancel := context.WithCancel(context.Background())
		return nil, dummyCancel, fmt.Errorf("http req %s: %v", url, err)
	}
	ctx, cancel := context.WithTimeout(req.Context(), timeout)

	req = req.WithContext(ctx)

	req.Header.Add("User-Agent", "python-requests/2.28.2")
	client := http.DefaultClient

	res, err := client.Do(req)
	if err != nil {
		return nil, cancel, fmt.Errorf("http get %s: %v", url, err)
	}
	return res, cancel, nil
}

func httpGetData(url string, timeout time.Duration) ([]byte, error) {
	res, cancel, err := httpGet(url, timeout)
	defer cancel()
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, MaxResponseSize))
	if err != nil {
		return nil, err
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	return body, nil
}
