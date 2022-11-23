package gmtls

type Config struct {
	CaCert     string
	SignCert   string
	SignKey    string
	EnCert     string
	EnKey      string
	IsSMCrypto bool
}

const (
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304
)
