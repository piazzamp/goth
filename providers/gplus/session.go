package gplus

import (
	"encoding/json"
	"errors"
	"github.com/piazzamp/goth"
	"golang.org/x/net/context"
	//"golang.org/x/oauth2"
	"google.golang.org/appengine"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Session stores data during the auth process with Facebook.
type Session struct {
	AuthURL      string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

var cont context.Context
var mut sync.Mutex

func SetContext(r *http.Request) {
	mut.Lock()
	cont = appengine.NewContext(r)
	mut.Unlock()
}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the Google+ provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New("an AuthURL has not be set")
	}
	return s.AuthURL, nil
}

// Authorize the session with Google+ and return the access token to be stored for future use.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	token, err := p.config.Exchange(cont, params.Get("code"))
	if err != nil {
		return "", err
	}
	s.AccessToken = token.AccessToken
	s.RefreshToken = token.RefreshToken
	s.ExpiresAt = token.Expiry
	return token.AccessToken, err
}

// Marshal the session into a string
func (s Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s Session) String() string {
	return s.Marshal()
}

// UnmarshalSession will unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	sess := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(sess)
	return sess, err
}
