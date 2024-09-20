package main

import (
    "crypto/tls"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "net/url"
    "strings"
)

const (
    keycloakURL  = "https://15.207.114.27:8443"
    clientID     = "Blue"
    clientSecret = "rMkVkPtb8JPpB9IY1BkoDP4zTcYSlU3J"
    realm        = "master"
)

var client *http.Client

func init() {
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Note: Use this only for development
    }
    client = &http.Client{Transport: tr}
}

func checkAuthorization(token, resource string) (bool, error) {
    authzURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", keycloakURL, realm)
    data := url.Values{}
    data.Set("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
    data.Set("audience", clientID)
    data.Set("permission", resource)

    req, err := http.NewRequest("POST", authzURL, strings.NewReader(data.Encode()))
    if err != nil {
        return false, err
    }
    req.Header.Add("Authorization", "Bearer "+token)
    req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
    resp, err := client.Do(req)
    if err != nil {
        return false, err
    }
    defer resp.Body.Close()
    if resp.StatusCode == http.StatusOK {
        return true, nil
    }
    body, _ := ioutil.ReadAll(resp.Body)
    log.Printf("Authorization denied for resource %s. Response: %s", resource, string(body))
    return false, nil
}

func serveProtectedResource(w http.ResponseWriter, r *http.Request, resource string) {
    token := r.URL.Query().Get("token")
    if token == "" {
        // Redirect to Keycloak login if no token is provided
        authURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth", keycloakURL, realm)
        params := url.Values{
            "client_id":     {clientID},
            "redirect_uri":  {"http://15.207.114.27:7000/callback"},
            "response_type": {"code"},
            "scope":         {"openid profile email"},
        }
        http.Redirect(w, r, authURL+"?"+params.Encode(), http.StatusFound)
        return
    }

    authorized, err := checkAuthorization(token, resource)
    if err != nil {
        http.Error(w, fmt.Sprintf("Authorization check failed: %v", err), http.StatusInternalServerError)
        return
    }
    if !authorized {
        http.Error(w, "Insufficient permissions", http.StatusForbidden)
        return
    }

    http.ServeFile(w, r, resource+".jpg")
}

func main() {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        token := r.URL.Query().Get("token")
        if token == "" {
            // Redirect to Keycloak login if no token is provided
            authURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth", keycloakURL, realm)
            params := url.Values{
                "client_id":     {clientID},
                "redirect_uri":  {"http://15.207.114.27:7000/callback"},
                "response_type": {"code"},
                "scope":         {"openid profile email"},
            }
            http.Redirect(w, r, authURL+"?"+params.Encode(), http.StatusFound)
            return
        }

        // Check for authorization of the root resource
        authorized, err := checkAuthorization(token, "root")
        if err != nil {
            http.Error(w, fmt.Sprintf("Authorization check failed: %v", err), http.StatusInternalServerError)
            return
        }
        if !authorized {
            http.Error(w, "Insufficient permissions", http.StatusForbidden)
            return
        }

        // Display links to protected resources
        w.Header().Set("Content-Type", "text/html")
        fmt.Fprintf(w, `
            <html>
                <body>
                    <h1>Protected Resources</h1>
                    <ul>
                        <li><a href="/sea?token=%s">Sea</a></li>
                        <li><a href="/mountain?token=%s">Mountain</a></li>
                    </ul>
                </body>
            </html>
        `, token, token)
    })

    http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
        code := r.URL.Query().Get("code")
        if code == "" {
            http.Error(w, "Invalid authorization code", http.StatusBadRequest)
            return
        }

        // Exchange authorization code for access token
        tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", keycloakURL, realm)
        data := url.Values{}
        data.Set("grant_type", "authorization_code")
        data.Set("code", code)
        data.Set("redirect_uri", "http://15.207.114.27:7000/callback")
        data.Set("client_id", clientID)
        data.Set("client_secret", clientSecret)
        resp, err := client.PostForm(tokenURL, data)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        defer resp.Body.Close()

        var tokenResp struct {
            AccessToken string `json:"access_token"`
        }
        if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        // Redirect back to the root URL with the token
        http.Redirect(w, r, fmt.Sprintf("/?token=%s", tokenResp.AccessToken), http.StatusFound)
    })

    http.HandleFunc("/sea", func(w http.ResponseWriter, r *http.Request) {
        serveProtectedResource(w, r, "sea")
    })

    http.HandleFunc("/mountain", func(w http.ResponseWriter, r *http.Request) {
        serveProtectedResource(w, r, "mountain")
    })

    log.Fatal(http.ListenAndServe(":7000", nil))
}
