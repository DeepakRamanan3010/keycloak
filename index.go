package main

import (
        "encoding/json"
        "fmt"
        "log"
        "net/http"
        "net/url"
        "strings"
        "crypto/tls"
)

const (
        keycloakURL = "https://15.26.210.202:8443"
        clientID    = "Test"
        clientSecret = "qx1dHQ1ivPvHrnHRE5lpBsP0Vwf94m2"
        realm        = "master"
)

func main() {
        tr := &http.Transport{
                TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Skip TLS verification
        }
        client := &http.Client{Transport: tr}

        http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
                // Redirect to Keycloak authorization URL
                authURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth", keycloakURL, realm)
                params := url.Values{
                        "client_id":     {clientID},
                        "redirect_uri":  {"http://15.26.210.202:8000/callback"},
                        "response_type": {"code"},
                        "scope":         {"openid profile email"},
                }
                authURL += "?" + params.Encode()
                http.Redirect(w, r, authURL, http.StatusFound)
        })

        http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
                // Handle authorization code redirect from Keycloak
                code := r.URL.Query().Get("code")
                if code == "" {
                        http.Error(w, "Invalid authorization code", http.StatusBadRequest)
                        return
                }

                // Exchange authorization code for access token
                tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", keycloakURL, realm)
                tokenReq, err := http.NewRequest("POST", tokenURL, strings.NewReader(fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=http://15.206.210.202:8000/callback", code)))
                if err != nil {
                        http.Error(w, err.Error(), http.StatusInternalServerError)
                        return
                }
                tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
                tokenReq.SetBasicAuth(clientID, clientSecret)

                resp, err := client.Do(tokenReq) // Use the custom client here
                if err != nil {
                        http.Error(w, err.Error(), http.StatusInternalServerError)
                        return
                }
                defer resp.Body.Close()

                var tokenResp struct {
                        AccessToken string `json:"access_token"`
                }
                err = json.NewDecoder(resp.Body).Decode(&tokenResp)
                if err != nil {
                        http.Error(w, err.Error(), http.StatusInternalServerError)
                        return
                }

                // Use access token to authenticate user
                userInfoURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo", keycloakURL, realm)
                userInfoReq, err := http.NewRequest("GET", userInfoURL, nil)
                if err != nil {
                        http.Error(w, err.Error(), http.StatusInternalServerError)
                        return
                }
                userInfoReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenResp.AccessToken))

                resp, err = client.Do(userInfoReq) // Use the custom client here
                if err != nil {
                        http.Error(w, err.Error(), http.StatusInternalServerError)
                        return
                }
                defer resp.Body.Close()

                var userInfo struct {
                        Sub string `json:"sub"`
                }
                err = json.NewDecoder(resp.Body).Decode(&userInfo)
                if err != nil {
                        http.Error(w, err.Error(), http.StatusInternalServerError)
                        return
                }

                // If user is authenticated, serve index.html
                if userInfo.Sub != "" {
                        http.ServeFile(w, r, "index.html")
                } else {
                        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
                }
        })

        log.Fatal(http.ListenAndServe(":8000", nil))
}
