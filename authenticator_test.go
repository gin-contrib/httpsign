package httpsign

import (
	"fmt"
	"github.com/gin-contrib/httpsign/crypto"
	"github.com/gin-contrib/httpsign/validator"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/render"
	"github.com/stretchr/testify/assert"
)

const (
	readID                 = KeyID("read")
	writeID                = KeyID("write")
	invalidKeyID           = KeyID("invalid key")
	invaldAlgo             = "invalidAlgo"
	invalidSignature       = "Invalid Signature"
	requestNilBodySig      = "ewYjBILGshEmTDDMWLeBc9kQfIscSKxmFLnUBU/eXQCb0hrY1jh7U5SH41JmYowuA4p6+YPLcB9z/ay7OvG/Sg=="
	requestBodyContent     = "hello world"
	requestBodyDigest      = "SHA-256=uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="
	requestBodyFalseDigest = "SHA-256=fakeDigest="
	requestBodySig         = "s8MEyer3dSpSsnL0+mQvUYgKm2S4AEX+hsvKmeNI7wgtLFplbCZtt8YOcySZrCyYbOJdPF1NASDHfupSuekecg=="
	requestHost            = "kyber.network"
	requestHostSig         = "+qpk6uAlILo/1YV1ZDK2suU46fbaRi5guOyg4b6aS4nWqLi9u57V6mVwQNh0s6OpfrVZwAYaWHCmQFCgJiZ6yg=="
	algoHmacSha512         = "hmac-sha512"
)

var (
	hmacsha512        = &crypto.HmacSha512{}
	secrets = Secrets{
		Keys: map[KeyID]*Secret{
			readID: &Secret{
				Key:       "1234",
				Algorithm: hmacsha512,
			},
			writeID: &Secret{
				Key:       "5678",
				Algorithm: hmacsha512,
			},
		},
	}
	requiredHeaders = []string{"(request-target)", "date", "digest"}
	submitHeader    = []string{"(request-target)", "date", "digest"}
	submitHeader2   = []string{"(request-target)", "date", "digest", "host"}
	requestTime     = time.Date(2018, time.October, 22, 07, 00, 07, 00, time.UTC)
)

func runTest(secretKeys Secrets, headers []string, v []validator.Validator, req *http.Request) *gin.Context {
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
	req, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)
	c := runTest(secrets, requiredHeaders, nil, req)
	assert.Equal(t, http.StatusUnauthorized, c.Writer.Status())
	assert.Equal(t, ErrNoSignature, c.Errors[0])
}

func TestAuthenticatedHeaderInvalidSignature(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)
	req.Header.Set(authorizationHeader, "hello")
	c := runTest(secrets, requiredHeaders, nil, req)
	assert.Equal(t, http.StatusUnauthorized, c.Writer.Status())
	assert.Equal(t, ErrInvalidAuthorizationHeader, c.Errors[0])
}

func TestAuthenticatedHeaderWrongKey(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)
	sigHeader := generateSignature(invalidKeyID, algoHmacSha512, submitHeader, requestNilBodySig)
	req.Header.Set(authorizationHeader, sigHeader)
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	c := runTest(secrets, requiredHeaders, nil, req)
	assert.Equal(t, http.StatusBadRequest, c.Writer.Status())
	assert.Equal(t, ErrInvalidKeyID, c.Errors[0])
}

func TestAuthenticateDateNotAccept(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)
	sigHeader := generateSignature(readID, algoHmacSha512, submitHeader, requestNilBodySig)
	req.Header.Set(authorizationHeader, sigHeader)
	req.Header.Set("Date", time.Date(1990, time.October, 20, 0, 0, 0, 0, time.UTC).Format(http.TimeFormat))
	c := runTest(secrets, requiredHeaders, nil, req)
	assert.Equal(t, http.StatusBadRequest, c.Writer.Status())
	assert.Equal(t, validator.ErrDateNotInRange, c.Errors[0])
}

func TestAuthenticateInvalidRequiredHeader(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)
	invalidRequiredHeaders := []string{"date"}
	sigHeader := generateSignature(readID, algoHmacSha512, invalidRequiredHeaders, requestNilBodySig)
	req.Header.Set(authorizationHeader, sigHeader)

	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))

	c := runTest(secrets, requiredHeaders, nil, req)
	assert.Equal(t, http.StatusBadRequest, c.Writer.Status())
	assert.Equal(t, ErrHeaderNotEnough, c.Errors[0])
}

func TestAuthenticateInvalidAlgo(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
	require.NoError(t, err)
	sigHeader := generateSignature(readID, invaldAlgo, submitHeader, requestNilBodySig)
	req.Header.Set(authorizationHeader, sigHeader)
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))

	c := runTest(secrets, requiredHeaders, nil, req)
	assert.Equal(t, http.StatusBadRequest, c.Writer.Status())
	assert.Equal(t, ErrIncorrectAlgorithm, c.Errors[0])
}

func TestInvalidSign(t *testing.T) {
	req, err := http.NewRequest("GET", "/", nil)
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

	req, err := http.NewRequest("GET", "/", nil)
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

	req, err := http.NewRequest("POST", "/", strings.NewReader(sampleBodyContent))
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

	req, err := http.NewRequest("GET", "/", nil)
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

	req, err := http.NewRequest("POST", "/", strings.NewReader(sampleBodyContent))
	require.NoError(t, err)
	sigHeader := generateSignature(readID, algoHmacSha512, submitHeader, requestBodySig)
	req.Header.Set(authorizationHeader, sigHeader)
	req.Header.Set("Date", requestTime.Format(http.TimeFormat))
	req.Header.Set("Digest", requestBodyDigest)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body, err := ioutil.ReadAll(w.Result().Body)
	assert.NoError(t, err)
	assert.Equal(t, body, []byte(sampleBodyContent))
}

func TestHttpValidRequestHost(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.Default()
	auth := NewAuthenticator(secrets, WithValidator(mockValidator...))
	r.Use(auth.Authenticated())
	r.POST("/", httpTestPost)

	requestURL := fmt.Sprintf("http://%s/", requestHost)
	req, err := http.NewRequest("POST", requestURL, strings.NewReader(sampleBodyContent))
	assert.NoError(t, err)
	sigHeader := generateSignature(readID, algoHmacSha512, submitHeader2, requestHostSig)
	req.Header.Set(authorizationHeader, sigHeader)
	req.Header.Set("Date", requestTime.Format(http.TimeFormat))
	req.Header.Set("Digest", requestBodyDigest)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body, err := ioutil.ReadAll(w.Result().Body)
	assert.NoError(t, err)
	assert.Equal(t, body, []byte(sampleBodyContent))
}

func TestAuthenticatorGetSecret(t *testing.T) {
	type fields struct {
		secrets    Secrets
		validators []validator.Validator
		headers    []string
	}
	type args struct {
		keyID     KeyID
		algorithm string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Secret
		wantErr bool
	}{
		{
			name:   "Get secret by KeyID from map",
			fields: fields{
				secrets: Secrets{
					Keys: map[KeyID]*Secret{
						readID: &Secret{
							Key:       "1234",
							Algorithm: hmacsha512,
						},
						writeID: &Secret{
							Key:       "5678",
							Algorithm: hmacsha512,
						},
					},
				},
			},
			args: args{
				keyID:     readID,
				algorithm: algoHmacSha512,
			},
			want: &Secret{
				Key:       "1234",
				Algorithm: hmacsha512,
			},
			wantErr: false,
		},
		{
			name:   "Get secret by KeyID from Getter func",
			fields: fields{
				secrets: Secrets{
					Keys: map[KeyID]*Secret{},
					Get: func(id KeyID) (secret *Secret, b bool) {
						localKeys := map[KeyID]*Secret{
							readID: &Secret{
								Key:       "1234",
								Algorithm: hmacsha512,
							},
							writeID: &Secret{
								Key:       "5678",
								Algorithm: hmacsha512,
							},
						}

						secret, ok := localKeys[id]
						if !ok {
							return &Secret{}, false
						}

						return secret, true
					},
				},
			},
			args: args{
				keyID:     writeID,
				algorithm: algoHmacSha512,
			},
			want: &Secret{
				Key:       "5678",
				Algorithm: hmacsha512,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Authenticator{
				secrets:    tt.fields.secrets,
				validators: tt.fields.validators,
				headers:    tt.fields.headers,
			}
			got, err := a.getSecret(tt.args.keyID, tt.args.algorithm)
			if (err != nil) != tt.wantErr {
				t.Errorf("getSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getSecret() got = %v, want %v", got, tt.want)
			}
		})
	}
}
