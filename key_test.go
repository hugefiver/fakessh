package main

import (
	"crypto"
	"crypto/ed25519"
	"reflect"
	"testing"
)

//-----BEGIN PRIVATE KEY-----
//MC4CAQAwBQYDK2VwBCIEIC0/5gf05fFCPN5dF+9B6jEp4arYqOoKavt00ngyVpiS
//-----END PRIVATE KEY-----\n
var priKey = ed25519.PrivateKey{
	0x2d, 0x3f, 0xe6, 0x07, 0xf4, 0xe5, 0xf1, 0x42, 0x3c, 0xde, 0x5d, 0x17, 0xef, 0x41, 0xea, 0x31,
	0x29, 0xe1, 0xaa, 0xd8, 0xa8, 0xea, 0x0a, 0x6a, 0xfb, 0x74, 0xd2, 0x78, 0x32, 0x56, 0x98, 0x92,
	0xf0, 0x56, 0x8c, 0x5e, 0xf7, 0xc3, 0xa3, 0x15, 0xfd, 0x86, 0x79, 0xa8, 0xdc, 0x46, 0x86, 0x6e,
	0x5d, 0x46, 0xe5, 0xaf, 0x88, 0x44, 0x01, 0xdf, 0xb0, 0x85, 0x58, 0x02, 0x69, 0xdd, 0xc3, 0xfc,
}
var marshaled = []byte{
	0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41,
	0x54, 0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x4d, 0x43, 0x34, 0x43,
	0x41, 0x51, 0x41, 0x77, 0x42, 0x51, 0x59, 0x44, 0x4b, 0x32, 0x56, 0x77, 0x42, 0x43, 0x49, 0x45,
	0x49, 0x43, 0x30, 0x2f, 0x35, 0x67, 0x66, 0x30, 0x35, 0x66, 0x46, 0x43, 0x50, 0x4e, 0x35, 0x64,
	0x46, 0x2b, 0x39, 0x42, 0x36, 0x6a, 0x45, 0x70, 0x34, 0x61, 0x72, 0x59, 0x71, 0x4f, 0x6f, 0x4b,
	0x61, 0x76, 0x74, 0x30, 0x30, 0x6e, 0x67, 0x79, 0x56, 0x70, 0x69, 0x53, 0x0a, 0x2d, 0x2d, 0x2d,
	0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45,
	0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a,
}

func Test_marshalPriKey(t *testing.T) {

	tests := []struct {
		name    string
		key     crypto.PrivateKey
		want    []byte
		wantErr bool
	}{
		{
			"test_marshal_private_key",
			priKey,
			marshaled,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := marshalPriKey(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("marshalKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("marshalKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseKey(t *testing.T) {
	tests := []struct {
		name    string
		bytes   []byte
		wantErr bool
	}{
		{
			"test_ed25519_pri_key",
			[]byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIC0/5gf05fFCPN5dF+9B6jEp4arYqOoKavt00ngyVpiS
-----END PRIVATE KEY-----`),
			false,
		},
		{
			"test_rsa2048_pri_key",
			[]byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1dbB1P+z8J+aAcKgbK6/XIPl0hLSm8F4iy5u/bP8z0fHHZtZ
ipD2jgAbjlNsC9f9vUiOjkc5642OcEIlqiccbb1tQtHZH5LUXb6oFS5tqoQcbTvH
l4DzFanq5X4EUPVnCmlhJ8EYib5iXMuxaI+gXxV/7wyBdwzmchKTsDJ2hQkIvews
JHnG+l9zhzCgUHC/TknQGoxRXe3H76y4OMAp6Ef/RxlX8fvZ0mM94QW/Ny+gKO72
SJJ9V1pC206evBj9x6cuG6Eb3T8768vkzftVq94HZwQZbxSLucIGZ29koWbg9um7
r+4L9Q7UsicB0AiYTjbc+RgeKVGoH8y7M+9IZwIDAQABAoIBADa8FLs3hFB4GcyP
i86l4BeHL2FZLg1uNTOy+/f2hSRtY/shE4dTWbi5MFR65/IUJD+5/btPYfT4M9hq
JgfqoO06CmiLHD9nrvIb5hwd2TZHQJt5LLqL6CzIZHa/jc1HM0vH83VgiK5hS/4i
qVNxSARulWOT2OOnKqlSNflowUuFr5vY8C0WhOyxZbu/KPOEuyjukJLDsbtswhmh
rMXzAbXOhB7n6HMX/VGrOBzzrAfJFnUKpfnm8INCOXEtDd5JGCojIY7kZnoFct1z
HDAUQgeJG66GfA3xhjkRufG5iZa54K0oY/TRFR9GVfOxlmu4+bVlwg3WLzYc2+Vj
VWxvcsECgYEA8mbZN2SU/bExP+Q3i8YZX+M0f3/VCdwfl6nQQgwlL3Mto9wi/HVr
pv/AlPQg5ONOvEJdgcMh7N8ljDfEZhqHL8N1Iykeiffbsj2PkICM0KSSF4+aEX1k
CUAe9buNt/8+ZJKl+vFlIgIenbcpn6b47/jock4lqPIFcY7Bxu4Gd+ECgYEA4dW3
EgT3/9ryX3K8NaF3XUGjnTlNWLRD8rxCCAcJYVVXfjS9gWT2n2yEYsDqZI2T6TmG
ORJvgUgzDfhlzuoS/vBh58FqqnWilPmjwd9Fvbm9Nuqn0CyxtnWrgQ9zcNZrVlx3
ImE241IBk/6dFgT+a+j2djYLstHAUTVKlFERKUcCgYEAydw8J5TrPhjBGqPCXfOq
Td+3aDXcA0n8RSB0/Yt/q/QOndZEjFh8PaXdii2C9xkUCFJ77APDzK5HZm1KcHzG
90+dzJoBhIOTwOrjE0L6AQYLYvODKe1x0QJExf5aFk/IdZhqAH/l6Fw7grt1Pi6e
P7jYWdgaJIbnYZmwZSjy2gECgYEAnFgzfHMaKfQvFas95zcYhuRZXBB+nql13Qc+
A4azlMHbZ5ElnP4Dywz6fc+mteRaAP2FEd/UeEE+ry5HdT8R1ZMfhK2fpdD4tIA7
QY3MH3QGLY24jeNTSMkf6aKDvhuDhe9PvupkcG2mkAmWQNdGN/i5H898u9iAdvgY
4KNa6SMCgYBRq+2p8fj11NlFX9cUqBfN7oFJaNhHqF3FpWUx9ZGHBWOfJmzAKHUb
cctTBIasvgEDblKKi4lTyDOB1yFKG37WWTdPBig41WMWYslc7tHR0Pn+O3IVgP6m
/vG4cCB55wswbzhNcpL6OMMsHOtwx6vzXE6HjSuMU2+6xhb4I6Oeyw==
-----END RSA PRIVATE KEY-----
			`),
			false,
		},
		{
			"test_ecdsa256_pri_key",
			[]byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIE7JbpszFqKXoA4zDqAMb4l60rAUKE0C3yWIDhs8ak2DoAoGCCqGSM49
AwEHoUQDQgAEiVIr752vNMYbo4YRbY9z9BAoqPJ6PTRYF1ND3j8jPPoEsgiYBD5C
WqAzRvdkqsjszd1NU7R6p4zrHaff+j8v+w==
-----END EC PRIVATE KEY-----
			`),
			false,
		},
		{
			"test_ed25519_openssh_pri_key",
			[]byte(`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDnyB26gBomP4ZEwKQKdRv3IE7I41eD/P3bl3wpCsofmwAAAJjq6hP76uoT
+wAAAAtzc2gtZWQyNTUxOQAAACDnyB26gBomP4ZEwKQKdRv3IE7I41eD/P3bl3wpCsofmw
AAAEB8RdSULrkarVdk7gFRr+tTP0U+zkqiwqjnkiooLCUi1OfIHbqAGiY/hkTApAp1G/cg
TsjjV4P8/duXfCkKyh+bAAAAFHJvb3RAREVTS1RPUC1KUzlFMDVDAQ==
-----END OPENSSH PRIVATE KEY-----`),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := parseKey(tt.bytes)
			if (err != nil) != tt.wantErr || s == nil {
				t.Errorf("parseKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
