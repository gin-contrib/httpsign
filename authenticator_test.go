package httpsign

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-contrib/httpsign/crypto"
	"github.com/gin-contrib/httpsign/validator"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/render"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	readID                 = KeyID("read")
	writeID                = KeyID("write")
	invalidKeyID           = KeyID("invalid key")
	invaldAlgo             = "invalidAlgo"
	requestNilBodySig      = "ewYjBILGshEmTDDMWLeBc9kQfIscSKxmFLnUBU/eXQCb0hrY1jh7U5SH41JmYowuA4p6+YPLcB9z/ay7OvG/Sg=="
	requestBodyDigest      = "SHA-256=uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="
	requestBodyFalseDigest = "SHA-256=fakeDigest="
	requestBodySig         = "s8MEyer3dSpSsnL0+mQvUYgKm2S4AEX+hsvKmeNI7wgtLFplbCZtt8YOcySZrCyYbOJdPF1NASDHfupSuekecg=="
	requestHost            = "kyber.network"
	requestHostSig         = "+qpk6uAlILo/1YV1ZDK2suU46fbaRi5guOyg4b6aS4nWqLi9u57V6mVwQNh0s6OpfrVZwAYaWHCmQFCgJiZ6yg=="
	algoHmacSha512         = "hmac-sha512"
)

var (
	hmacsha512 = &crypto.HmacSha512{}
	secrets    = Secrets{
		readID: &Secret{
			Key:       "1234",
			Algorithm: hmacsha512,
		},
		writeID: &Secret{
			Key:       "5678",
			Algorithm: hmacsha512,
		},
	}
	requiredHeaders = []string{requestTarget, date, digest}
	submitHeader    = []string{requestTarget, date, digest}
	submitHeader2   = []string{requestTarget, date, digest, "host"}
	requestTime     = time.Date(2018, time.October, 22, 0o7, 0o0, 0o7, 0o0, time.UTC)
)

func runTest(
	secretKeys Secrets,
	headers []string,
	v []validator.Validator,
	req *http.Request,
) *gin.Context {
	gin.SetMode(gin.TestMode)
	auth := NewAuthenticator(secretKeys, WithRequiredHeaders(headers), WithValidator(v...))
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = req
	auth.Authenticated()(c)
	return c
}

func generateSignature(keyID KeyID, algorithm string, headers []string, signature string) string {
	return fmt.Sprintf(
		"Signature keyId=\"%s\",algorithm=\"%s\",headers=\"%s\",signature=\"%s\"",
		keyID, algorithm, strings.Join(headers, " "), signature,
	)
}

func TestAuthenticatedHeaderNoSignature(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	require.NoError(t, err)
	c := runTest(secrets, requiredHeaders, nil, req)
	assert.Equal(t, http.StatusUnauthorized, c.Writer.Status())
	assert.Equal(t, ErrNoSignature, c.Errors[0])
}

func TestAuthenticatedHeaderInvalidSignature(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	require.NoError(t, err)
	req.Header.Set(authorizationHeader, "hello")
	c := runTest(secrets, requiredHeaders, nil, req)
	assert.Equal(t, http.StatusUnauthorized, c.Writer.Status())
	assert.Equal(t, ErrInvalidAuthorizationHeader, c.Errors[0])
}

func TestAuthenticatedHeaderWrongKey(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	require.NoError(t, err)
	sigHeader := generateSignature(invalidKeyID, algoHmacSha512, submitHeader, requestNilBodySig)
	req.Header.Set(authorizationHeader, sigHeader)
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	c := runTest(secrets, requiredHeaders, nil, req)
	assert.Equal(t, http.StatusUnauthorized, c.Writer.Status())
	assert.Equal(t, ErrInvalidKeyID, c.Errors[0])
}

func TestAuthenticateDateNotAccept(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	require.NoError(t, err)
	sigHeader := generateSignature(readID, algoHmacSha512, submitHeader, requestNilBodySig)
	req.Header.Set(authorizationHeader, sigHeader)
	req.Header.Set(
		"Date",
		time.Date(1990, time.October, 20, 0, 0, 0, 0, time.UTC).Format(http.TimeFormat),
	)
	c := runTest(secrets, requiredHeaders, nil, req)
	assert.Equal(t, http.StatusBadRequest, c.Writer.Status())
	assert.Equal(t, validator.ErrDateNotInRange, c.Errors[0])
}

func TestAuthenticateInvalidRequiredHeader(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	require.NoError(t, err)
	invalidRequiredHeaders := []string{date}
	sigHeader := generateSignature(
		readID,
		algoHmacSha512,
		invalidRequiredHeaders,
		requestNilBodySig,
	)
	req.Header.Set(authorizationHeader, sigHeader)

	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))

	c := runTest(secrets, requiredHeaders, nil, req)
	assert.Equal(t, http.StatusBadRequest, c.Writer.Status())
	assert.Equal(t, ErrHeaderNotEnough, c.Errors[0])
}

func TestAuthenticateInvalidAlgo(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	require.NoError(t, err)
	sigHeader := generateSignature(readID, invaldAlgo, submitHeader, requestNilBodySig)
	req.Header.Set(authorizationHeader, sigHeader)
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))

	c := runTest(secrets, requiredHeaders, nil, req)
	assert.Equal(t, http.StatusBadRequest, c.Writer.Status())
	assert.Equal(t, ErrIncorrectAlgorithm, c.Errors[0])
}

func TestInvalidSign(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	require.NoError(t, err)
	sigHeader := generateSignature(readID, algoHmacSha512, submitHeader, requestNilBodySig)
	req.Header.Set(authorizationHeader, sigHeader)
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))

	c := runTest(secrets, requiredHeaders, nil, req)
	assert.Equal(t, http.StatusUnauthorized, c.Writer.Status())
	assert.Equal(t, ErrInvalidSign, c.Errors[0])
}

// mock interface always return true
type dateAlwaysValid struct{}

func (v *dateAlwaysValid) Validate(r *http.Request) error { return nil }

var mockValidator = []validator.Validator{
	&dateAlwaysValid{},
	validator.NewDigestValidator(),
}

func httpTestGet(c *gin.Context) {
	c.JSON(http.StatusOK,
		gin.H{
			"success": true,
		})
}

func httpTestPost(c *gin.Context) {
	body, err := c.GetRawData()
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
	}
	c.Render(http.StatusOK, render.Data{Data: body})
}

func TestHttpInvalidRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.Default()
	auth := NewAuthenticator(secrets, WithValidator(mockValidator...))
	r.Use(auth.Authenticated())
	r.GET("/", httpTestGet)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	require.NoError(t, err)
	sigHeader := generateSignature(readID, algoHmacSha512, submitHeader, requestBodySig)
	req.Header.Set(authorizationHeader, sigHeader)
	req.Header.Set("Date", requestTime.Format(http.TimeFormat))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.NotEqual(t, http.StatusOK, w.Code)
}

func TestHttpInvalidDigest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.Default()
	auth := NewAuthenticator(secrets, WithValidator(mockValidator...))
	r.Use(auth.Authenticated())
	r.POST("/", httpTestPost)

	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"/",
		strings.NewReader(sampleBodyContent),
	)
	require.NoError(t, err)
	sigHeader := generateSignature(readID, algoHmacSha512, submitHeader, requestBodySig)
	req.Header.Set(authorizationHeader, sigHeader)
	req.Header.Set("Date", requestTime.Format(http.TimeFormat))
	req.Header.Set("Digest", requestBodyFalseDigest)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHttpValidRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.Default()
	auth := NewAuthenticator(secrets, WithValidator(mockValidator...))
	r.Use(auth.Authenticated())
	r.GET("/", httpTestGet)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	require.NoError(t, err)
	sigHeader := generateSignature(readID, algoHmacSha512, submitHeader, requestNilBodySig)
	req.Header.Set(authorizationHeader, sigHeader)
	req.Header.Set("Date", requestTime.Format(http.TimeFormat))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHttpValidRequestBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.Default()
	auth := NewAuthenticator(secrets, WithValidator(mockValidator...))
	r.Use(auth.Authenticated())
	r.POST("/", httpTestPost)

	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"/",
		strings.NewReader(sampleBodyContent),
	)
	require.NoError(t, err)
	sigHeader := generateSignature(readID, algoHmacSha512, submitHeader, requestBodySig)
	req.Header.Set(authorizationHeader, sigHeader)
	req.Header.Set("Date", requestTime.Format(http.TimeFormat))
	req.Header.Set("Digest", requestBodyDigest)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body, err := io.ReadAll(w.Result().Body)
	require.NoError(t, err)
	assert.Equal(t, body, []byte(sampleBodyContent))
}

func TestHttpValidRequestHost(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.Default()
	auth := NewAuthenticator(secrets, WithValidator(mockValidator...))
	r.Use(auth.Authenticated())
	r.POST("/", httpTestPost)

	requestURL := fmt.Sprintf("http://%s/", requestHost)
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		requestURL,
		strings.NewReader(sampleBodyContent),
	)
	require.NoError(t, err)
	sigHeader := generateSignature(readID, algoHmacSha512, submitHeader2, requestHostSig)
	req.Header.Set(authorizationHeader, sigHeader)
	req.Header.Set("Date", requestTime.Format(http.TimeFormat))
	req.Header.Set("Digest", requestBodyDigest)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body, err := io.ReadAll(w.Result().Body)
	require.NoError(t, err)
	assert.Equal(t, body, []byte(sampleBodyContent))
}

func TestConstructSignMessageRepeatedHeaders(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{name: "missing", want: ""},
		{name: "single", values: []string{"max-age=60"}, want: "max-age=60"},
		{
			name:   "repeated",
			values: []string{"max-age=60", "must-revalidate"},
			want:   "max-age=60, must-revalidate",
		},
		{
			name:   "reversed",
			values: []string{"must-revalidate", "max-age=60"},
			want:   "must-revalidate, max-age=60",
		},
		{
			name:   "combined",
			values: []string{"max-age=60, must-revalidate"},
			want:   "max-age=60, must-revalidate",
		},
		{
			name:   "three values",
			values: []string{"first", "second", "third"},
			want:   "first, second, third",
		},
		{name: "empty first", values: []string{"", "second"}, want: ", second"},
		{name: "empty last", values: []string{"first", ""}, want: "first, "},
		{
			name:   "quoted comma",
			values: []string{`first="a,b"`, "second"},
			want:   `first="a,b", second`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.org/foo?bar=baz", nil)
			for _, value := range tc.values {
				req.Header.Add("Cache-Control", value)
			}
			req.Header.Set("X-Other", "kept")
			message := constructSignMessage(
				req,
				[]string{requestTarget, host, "cache-control", "x-other"},
			)
			want := "(request-target): get /foo?bar=baz\nhost: example.org\ncache-control: " + tc.want + "\nx-other: kept"
			assert.Equal(t, want, message)
			assert.Equal(t, tc.values, req.Header.Values("Cache-Control"))
		})
	}
}

func TestHttpRepeatedSignatureHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	headers := []string{requestTarget, date, digest, "cache-control"}
	router := gin.New()
	auth := NewAuthenticator(secrets, WithRequiredHeaders(headers))
	router.Use(auth.Authenticated())
	router.GET("/foo", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	server := httptest.NewServer(router)
	defer server.Close()

	tests := []struct {
		name   string
		values []string
		signed string
	}{
		{name: "single", values: []string{"max-age=60"}, signed: "max-age=60"},
		{
			name:   "combined",
			values: []string{"max-age=60, must-revalidate"},
			signed: "max-age=60, must-revalidate",
		},
		{
			name:   "repeated",
			values: []string{"max-age=60", "must-revalidate"},
			signed: "max-age=60, must-revalidate",
		},
		{
			name:   "reversed",
			values: []string{"must-revalidate", "max-age=60"},
			signed: "must-revalidate, max-age=60",
		},
		{
			name:   "three values",
			values: []string{"first", "second", "third"},
			signed: "first, second, third",
		},
		{
			name:   "quoted comma",
			values: []string{`first="a,b"`, "second"},
			signed: `first="a,b", second`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				server.URL+"/foo?bar=baz",
				nil,
			)
			require.NoError(t, err)
			for _, value := range tc.values {
				req.Header.Add("Cache-Control", value)
			}
			dateValue := time.Now().UTC().Format(http.TimeFormat)
			req.Header.Set("Date", dateValue)
			message := "(request-target): get /foo?bar=baz\ndate: " + dateValue + "\ndigest: \ncache-control: " + tc.signed
			signature, err := hmacsha512.Sign(message, secrets[readID].Key)
			require.NoError(t, err)
			req.Header.Set(
				authorizationHeader,
				generateSignature(
					readID,
					algoHmacSha512,
					headers,
					base64.StdEncoding.EncodeToString(signature),
				),
			)

			response, err := server.Client().Do(req)
			require.NoError(t, err)
			defer response.Body.Close()
			assert.Equal(t, http.StatusNoContent, response.StatusCode)
		})
	}
}
