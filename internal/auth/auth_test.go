package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		headers        http.Header
		expectedAPIKey string
		expectedError  error
	}{
		{
			name:           "No Authorization Header",
			headers:        http.Header{},
			expectedAPIKey: "",
			expectedError:  ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header - Missing ApiKey Prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer someapikey"},
			},
			expectedAPIKey: "",
			expectedError:  errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Authorization Header - Missing Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedAPIKey: "",
			expectedError:  errors.New("malformed authorization header"),
		},
		{
			name: "Valid Authorization Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey someapikey"},
			},
			expectedAPIKey: "someapikey",
			expectedError:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(test.headers)

			// Check API key
			if apiKey != test.expectedAPIKey {
				t.Errorf("expected API key %q, got %q", test.expectedAPIKey, apiKey)
			}

			// Check error
			if (err != nil && test.expectedError == nil) ||
				(err == nil && test.expectedError != nil) ||
				(err != nil && test.expectedError != nil && err.Error() != test.expectedError.Error()) {
				t.Errorf("expected error %q, got %q", test.expectedError, err)
			}
		})
	}
}
