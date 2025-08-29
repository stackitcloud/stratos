package cfappssh_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/cloudfoundry/stratos/src/jetstream/plugins/cfappssh"
)

func TestCheckForV3Availability(t *testing.T) {
	expectedProcessID := "i-am-process-id"
	appGUID := "some-guid"

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		appWebProcess := map[string]string{
			"AppGUID": "one two three",
			"guid":    "i-am-process-id",
			"Type":    "web",
		}
		re := regexp.MustCompile("^/v3")

		if re.Match([]byte(r.URL.Path)) && r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == fmt.Sprintf("/v3/apps/%s/processes/web", appGUID) && r.Method == http.MethodGet {
			body, err := json.Marshal(appWebProcess)
			if err != nil {
				t.Error("failed creating response body")
			}
			w.WriteHeader(http.StatusOK)

			w.Write(body)
			return
		}
	}))
	defer testServer.Close()

	apiClient := http.Client{}
	processID, err := cfappssh.CheckForV3AvailabilityAndReturnProcessID(appGUID, testServer.URL, "","", apiClient)
	if err != nil {
		t.Errorf("I didn't expect that: %s", err)
	}
	if processID != expectedProcessID {
		t.Errorf("the value should have changed to %s but was %s", expectedProcessID, appGUID)
	}
}

func TestV2InstanceWebProcessSSH(t *testing.T) {
	expectedProcessID := "some-guid"
	appGUID := "some-guid"
	t.Parallel()

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		re := regexp.MustCompile("^/v3")
		t.Log("path", r.URL.Path, "method", r.Method)

		if re.Match([]byte(r.URL.Path)) && r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}))
	defer testServer.Close()

	apiClient := http.Client{}
	processID, err := cfappssh.CheckForV3AvailabilityAndReturnProcessID(appGUID, testServer.URL, "","", apiClient)
	if err != nil {
		t.Errorf("I didn't expect that: %s", err)
	}
	if processID != expectedProcessID {
		t.Errorf("the value should NOT have changed. expected %s but was %s", expectedProcessID, processID)
	}
}
