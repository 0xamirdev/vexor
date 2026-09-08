package detect

import (
	"fmt"
	"hash/fnv"
	"net/url"

	"github.com/0xamirdev/vexor/internal/httpc"
)

// fnvNew32a wraps fnv hashing with a constructor that never fails.
func fnvNew32a() interface {
	Write(p []byte) (n int, err error)
	Sum32() uint32
} {
	return fnv.New32a()
}

// sprintf is fmt.Sprintf minus the import noise in probe files.
func sprintf(format string, args ...interface{}) string {
	return fmt.Sprintf(format, args...)
}

// pointValuesWith clones the original point values and substitutes payload.
func pointValuesWith(p Point, payload string) url.Values {
	vals := url.Values{}
	for k, vs := range p.Values {
		for _, v := range vs {
			vals.Add(k, v)
		}
	}
	if p.Param != "" {
		vals.Set(p.Param, payload)
	}
	return vals
}

// httpcCurl forwards to httpc.Curl.
func httpcCurl(method, rawURL string, vals url.Values) string {
	return httpc.Curl(method, rawURL, vals)
}
