package cfappssh

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	cloudFoundryResource "code.cloudfoundry.org/cli/resources"
	"github.com/cloudfoundry/stratos/src/jetstream/api"
	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// See: https://docs.cloudfoundry.org/devguide/deploy-apps/ssh-apps.html

// WebScoket code based on: https://github.com/gorilla/websocket/blob/master/examples/command/main.go

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Inactivity timeout
	inActivityTimeout = 10 * time.Second

	md5FingerprintLength          = 47 // inclusive of space between bytes
	base64Sha256FingerprintLength = 43
)

// Allow connections from any Origin
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// KeyCode - JSON object that is passed from the front-end to notify of a key press or a term resize
type KeyCode struct {
	Key  string `json:"key"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

func CheckForV3AvailabilityAndReturnProcessID(appID, baseURL, clientID, token string, apiClient http.Client) (string, error) {
	resp, err := apiClient.Head(fmt.Sprintf("%s/%s", baseURL, "v3"))
	if resp.StatusCode == http.StatusNotFound {
		return appID, nil
	}
	if resp.StatusCode == http.StatusOK {
    	processRequest, err := prepareRequest(baseURL, clientID, token, fmt.Sprintf("/v3/apps/%s/processes/web", appID))
		if err != nil {
			return appID, sendSSHError("failed preparing v3 request: %s", err)
		}
		resp, err := apiClient.Do(processRequest)
		if err != nil {
			return appID, sendSSHError("failed checking for processes of app_guid %s => '%s': %s", processRequest.URL.Path, appID, err)
		}
		defer resp.Body.Close()
		respBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return appID, sendSSHError("failed reading response for '%s': %s", resp.Request.URL.Path , err)
		}
	    appWebProcess := &cloudFoundryResource.Process{}
		err = appWebProcess.UnmarshalJSON(respBytes);
		if err != nil {
			return appID, sendSSHError("failed unmarshaling response: '%s' for app_guid '%s': %s", string(respBytes), appID, err)
		}
		if appWebProcess.GUID == "" {
			return appID, sendSSHError("the processID returned was empty: %s", string(respBytes))
		}
		return appWebProcess.GUID, nil
	}
	return appID, err
}
func (cfAppSsh *CFAppSSH) appSSH(c echo.Context) error {
	// Need to get info for the endpoint
	// Get the CNSI and app IDs from route parameters
	cnsiGUID := c.Param("cnsiGuid")
	userGUID := c.Get("user_id").(string)

	var p = cfAppSsh.portalProxy

	// Extract the Doppler endpoint from the CNSI record
	cnsiRecord, err := p.GetCNSIRecord(cnsiGUID)
	if err != nil {
		return sendSSHError("Could not get endpoint information")
	}

	// Make the info call to the SSH endpoint info
	// Currently this is not cached, so we must get it each time
	apiEndpoint := cnsiRecord.APIEndpoint

	cfPlugin, err := p.GetEndpointTypeSpec("cf")

	if err != nil {
		return sendSSHError("Can not get Cloud Foundry endpoint plugin")
	}

	_, info, err := cfPlugin.Info(apiEndpoint.String(), cnsiRecord.SkipSSLValidation, cnsiRecord.CACert)
	if err != nil {
		return sendSSHError("Can not get Cloud Foundry info")
	}

	cfInfoEndpoint, found := info.(api.EndpointInfo)
	if !found {
		return sendSSHError("Can not get Cloud Foundry Endpoint info")
	}
	cfInfo := cfInfoEndpoint.V2Info

	appOrProcessGUID := c.Param("appGuid")

	// Refresh token first - makes sure it will be valid when we make the request to get the code
	refreshedTokenRec, err := p.RefreshOAuthToken(cnsiRecord.SkipSSLValidation, cnsiRecord.GUID, userGUID, cnsiRecord.ClientId, cnsiRecord.ClientSecret, cnsiRecord.TokenEndpoint)
	if err != nil {
		return sendSSHError("Couldn't get refresh token for CNSI with GUID %s", cnsiRecord.GUID)
	}
	// use processID instead of appGUID if we detect V3 availability. V3 apps can have multiple containers within one instance and therefore cannot use the appGUID
	// because that appGUID could wrap multiple processIDs each with their own option to connect.
	// Until full V3 support is added, this will allow targetting the WEB process only. This is not a limitation of the go code. It intentionally left out for now because
	// the UI does not provide an option to choose the nested process container.
	appOrProcessGUID, err = CheckForV3AvailabilityAndReturnProcessID(appOrProcessGUID, apiEndpoint.String(), cnsiRecord.ClientId, string(refreshedTokenRec.AuthToken), p.GetHttpClient(cnsiRecord.SkipSSLValidation, cnsiRecord.CACert))
	if err != nil {
		return sendSSHError("Failed checking for v3 app: %s", err)
	}

	appInstance := c.Param("appInstance")

	host, _, err := net.SplitHostPort(cfInfo.AppSSHEndpoint)
	if err != nil {
		host = cfInfo.AppSSHEndpoint
	}

	// Build the Username
	// cf:APP-GUID/APP-INSTANCE-INDEX@SSH-ENDPOINT
	username := fmt.Sprintf("cf:%s/%s@%s", appOrProcessGUID, appInstance, host)

	// Need to get SSH Code


	code, err := getSSHCode(cnsiRecord.TokenEndpoint, cfInfo.AppSSHOauthCLient, refreshedTokenRec.AuthToken, cnsiRecord.SkipSSLValidation)
	if err != nil {
		return sendSSHError("Couldn't get SSH Code: %s", err)
	}
	sshConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(code),
		},

		HostKeyCallback: sshHostKeyChecker(cfInfo.AppSSHHostKeyFingerprint),
	}

	connection, err := ssh.Dial("tcp", cfInfo.AppSSHEndpoint, sshConfig)
	if err != nil {
		return sendSSHError("Failed to dial '%s': %s", username, err)
	}

	session, err := connection.NewSession()
	if err != nil {
		return sendSSHError("Failed to create session: %s", err)
	}

	defer connection.Close()

	// Upgrade the web socket
	ws, pingTicker, err := api.UpgradeToWebSocket(c)
	if err != nil {
		return err
	}
	defer ws.Close()
	defer pingTicker.Stop()

	modes := ssh.TerminalModes{
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	// NB: rows, cols
	if err := session.RequestPty("xterm", 84, 80, modes); err != nil {
		session.Close()
		return sendSSHError("request for pseudo terminal failed: %s", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return sendSSHError("Unable to setup stdin for session: %v", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		return sendSSHError("Unable to setup stdout for session: %v", err)
	}

	defer session.Close()

	stdoutDone := make(chan struct{})
	go pumpStdout(ws, stdout, stdoutDone)
	go session.Shell()

	// Read the input from the web socket and pipe it to the SSH client
	for {
		_, r, err := ws.ReadMessage()
		if err != nil {
			log.Error("Error reading message from web socket")
			log.Warnf("%+v", err)
			return err
		}

		res := KeyCode{}
		json.Unmarshal(r, &res)

		if res.Cols == 0 {
			stdin.Write([]byte(res.Key))
		} else {
			// Terminal resize request
			if err := windowChange(session, res.Rows, res.Cols); err != nil {
				log.Error("Can not resize the PTY")
			}
		}
	}
}

func sendSSHError(format string, a ...interface{}) error {
	if len(a) == 0 {
		log.Error("App SSH Error: " + format)
	} else {
		log.Errorf("App SSH Error: "+format, a)
	}
	return echo.NewHTTPError(http.StatusInternalServerError, fmt.Errorf(format, a...))
}

func sshHostKeyChecker(fingerprint string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		switch len(fingerprint) {
		case base64Sha256FingerprintLength:
			if fmt.Sprintf("SHA256:%s", fingerprint) == ssh.FingerprintSHA256(key) {
				return nil
			}
		case md5FingerprintLength:
			if fingerprint == ssh.FingerprintLegacyMD5(key) {
				return nil
			}
		default:
			return errors.New("Unsupported host key fingerprint format")
		}
		return errors.New("Host key fingerprint is incorrect")
	}
}

// RFC 4254 Section 6.7.
type windowChangeRequestMsg struct {
	Columns uint32
	Rows    uint32
	Width   uint32
	Height  uint32
}

func windowChange(s *ssh.Session, h, w int) error {

	req := windowChangeRequestMsg{
		Columns: uint32(w),
		Rows:    uint32(h),
		Width:   uint32(w * 8),
		Height:  uint32(h * 8),
	}
	ok, err := s.SendRequest("window-change", true, ssh.Marshal(&req))
	if err == nil && !ok {
		err = errors.New("ssh: window-change failed")
	}
	return err
}

func pumpStdout(ws *websocket.Conn, r io.Reader, done chan struct{}) {
	buffer := make([]byte, 32768)
	for {
		len, err := r.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Errorf("App SSH encountered an error reading from stdout; %v", err)
			}
			ws.Close()
			break
		}

		ws.SetWriteDeadline(time.Now().Add(writeWait))
		bytes := fmt.Sprintf("% x\n", buffer[:len])
		if err := ws.WriteMessage(websocket.TextMessage, []byte(bytes)); err != nil {
			log.Error("App SSH Failed to write nessage")
			ws.Close()
			break
		}
	}
}

// ErrPreventRedirect - Error to indicate a redirect - used to make a redirect that we want to prevent later
var ErrPreventRedirect = errors.New("prevent-redirect")

func prepareRequest(authorizeEndpoint, clientID, token, path string) (*http.Request, error) {
	authorizeURL, err := url.Parse(authorizeEndpoint)
	if err != nil {
		return nil, err
	}

	values := url.Values{}
	values.Set("response_type", "code")
	values.Set("grant_type", "authorization_code")
	values.Set("client_id", clientID)

	authorizeURL.Path += path
	authorizeURL.RawQuery = values.Encode()

	authorizeReq, err := http.NewRequest("GET", authorizeURL.String(), nil)
	if err != nil {
		return nil, err
	}

	authorizeReq.Header.Add("authorization", "Bearer "+token)

	return authorizeReq, nil
}
func getClientWithoutRedirects(skipSSLValidation bool) *http.Client{
	return &http.Client{
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return ErrPreventRedirect
		},
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipSSLValidation,
			},
			Proxy:               http.ProxyFromEnvironment,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
}

func getSSHCode(authorizeEndpoint, clientID, token string, skipSSLValidation bool) (string, error) {
    authorizeReq, err := prepareRequest(authorizeEndpoint, clientID, token, "/oauth/authorize")
	if err != nil {
		return "", sendSSHError("Failed preparing request %s", err)
	}
	httpClientWithoutRedirects := getClientWithoutRedirects(skipSSLValidation)


	resp, err := httpClientWithoutRedirects.Do(authorizeReq)
	if resp != nil {
		log.Infof("%+v", resp)
	}
	if err == nil {
		return "", errors.New("Authorization server did not redirect with one time code")
	}

	if netErr, ok := err.(*url.Error); !ok || netErr.Err != ErrPreventRedirect {
		return "", errors.New("Error requesting one time code from server")
	}

	loc, err := resp.Location()
	if err != nil {
		return "", errors.New("Error getting the redirected location")
	}

	codes := loc.Query()["code"]
	if len(codes) != 1 {
		return "", errors.New("Unable to acquire one time code from authorization response")
	}

	return codes[0], nil
}
