// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"

	"github.com/containerd/containerd/cio"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

const (
	splunkTokenKey              = "--splunk-token"
	splunkUrlkey                = "--splunk-url"
	splunkInsecureskipverifyKey = "--splunk-insecureskipverify"
	testSplunkUrl               = "https://localhost:8089"
)

var testSplunk = func(token string) {
	// These tests are run in serial because we only define one log driver instance.
	ginkgo.Describe("splunk shim logger", ginkgo.Serial, func() {
		ginkgo.It("should send logs to splunk log driver", func() {
			args := map[string]string{
				logDriverTypeKey:            splunkDriverName,
				containerIdKey:              testContainerId,
				containerNameKey:            testContainerName,
				splunkTokenKey:              token,
				splunkUrlkey:                testSplunkUrl,
				splunkInsecureskipverifyKey: "true",
			}
			creator := cio.BinaryIO(*Binary, args)
			sendTestLogByContainerd(creator, testLog)
			validateTestLogsInSplunk(testSplunkUrl, token, testLog)
		})
	})
}

func validateTestLogsInSplunk(url string, token string, testLog string) {
	// Use REST API to retrieve the logs. https://docs.splunk.com/Documentation/Splunk/9.1.1/RESTREF/RESTsearch#search.2Fjobs
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	fmt.Println("tokenizing" + token)
	client := &http.Client{Transport: tr}
	searchQuery := "search '*' | head 1" // Get the latest of all the log events.
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/services/search/jobs", url), bytes.NewBufferString(searchQuery))
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", fmt.Sprintf("Splunk %s", token)) // https://docs.splunk.com/Documentation/Splunk/9.1.1/Security/UseAuthTokens
	resp, err := client.Do(req)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())
	fmt.Println(string(body))
}
