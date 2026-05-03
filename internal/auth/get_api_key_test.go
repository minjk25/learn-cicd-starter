package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	test_cases := []struct {
		name         string
		inputKey     string
		inputVal     string
		expectedPass string
		expectedErr  string
	}{
		{
			name:         "empty header",
			inputKey:     "",
			inputVal:     "",
			expectedPass: "",
			expectedErr:  "no authorization header included",
		},
		{
			name:         "empty value",
			inputKey:     "Authorization",
			inputVal:     "",
			expectedPass: "",
			expectedErr:  "no authorization header included",
		},
		{
			name:         "malformed header1",
			inputKey:     "Authorization",
			inputVal:     "ApiKe some-API-key",
			expectedPass: "",
			expectedErr:  "malformed authorization header",
		},
		{
			name:         "malformed header2",
			inputKey:     "Authorization",
			inputVal:     "ApiKeysome-API-key",
			expectedPass: "",
			expectedErr:  "malformed authorization header",
		},
		{
			name:         "malformed header3",
			inputKey:     "Authorization",
			inputVal:     "Bearer some-API-key",
			expectedPass: "",
			expectedErr:  "malformed authorization header",
		},
		{
			name:         "valid header",
			inputKey:     "Authorization",
			inputVal:     "ApiKey some-API-key",
			expectedPass: "some-API-key",
			expectedErr:  "",
		},
	}

	for _, tc := range test_cases {
		t.Run(tc.name, func(t *testing.T) {
			header := http.Header{}
			header.Add(tc.inputKey, tc.inputVal)

			actual, err := GetAPIKey(header)
			if tc.expectedErr != "" {
				// unhappy cases
				if err == nil {
					t.Errorf("expected error: %q \nbut got none", tc.expectedErr)
					return
				}
				if err.Error() != tc.expectedErr {
					t.Errorf("expected error: %q \ngot %q", tc.expectedErr, err.Error())
				}
			} else {
				// happy cases
				if err != nil {
					t.Errorf("expected no error \ngot %v", err)
					return
				}
				if actual != tc.expectedPass {
					t.Errorf("expected %q \ngot %q", tc.expectedPass, actual)
				}
			}

		})
	}
}
