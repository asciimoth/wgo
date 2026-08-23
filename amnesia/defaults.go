package amnezia

// DefaultOfficialRelease identifies the official artifact from which the
// release-injected public defaults below were verified.
const DefaultOfficialRelease = "5.0.1.5"

// DefaultOfficialCommit is the source commit associated with
// DefaultOfficialRelease.
const DefaultOfficialCommit = "7d4f3e0f5090b74903609179653d1f669d2ad08a"

// DefaultGatewayURL is the production gateway compiled into the official app.
const DefaultGatewayURL = "http://gw.amnezia.org:80/"

// DefaultOfficialAppVersion and DefaultOfficialCLIName are the compatibility
// metadata sent by the verified official release. Callers may override both.
const (
	DefaultOfficialAppVersion = DefaultOfficialRelease
	DefaultOfficialCLIName    = "AmneziaVPN"
)

// DefaultGatewayPublicKeyPEM is the production RSA encryption key embedded in
// the official app. It is a public key, not an API credential. The missing
// final newline is intentional: S3 proxy-list key derivation hashes these exact
// bytes.
const DefaultGatewayPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAj5mxl/4DL3Sk89ntxs5G
X3JawGQWIoq6rvNkOzNGuNgedNS2+pi6hZl3Izl1Io9om4KiUlMT6mgLO1hTr9q+
s7CYhlvroFA7ErucF+9L+7FCt0Igi0kIK/R2/vxd/2HaUrorn/aSvvutkYwbfxqW
SwtzE+RuBeDWGvEt937OW0oqYONPYv9E4T56Dz/EZ6v2t8ejAnKLbGD/GocMmipK
7etFSiSMAB2RmaztqTq4NleBepfO80XpYlW9pCSXuHcE8wxHczkzxsbyMAMsG/K3
vUQY6qPtohqqzSSBwa/8u2ptNHBeor7l7DdYXeR/Nqcc4z92VUkZ5lOVR4evkS5V
/wQqp5tnOJEj3NjUhEhXFoNEapbZd1bh6iQoUk7jC1TdvKJ/nPKGZAsHRpr0rNKz
fx/N/Oo6lr2yh/+ps6VxTkbPmB6E85WOO3UvjImZUY0XQdBjWle/4iJLdEC77Nr0
jXhdgeypucy6jkB6iBHMeVMlrNMEV7UxoBR/cCNx55zu/8sml5ByiDvCDT7sRomN
NgVt5S/FaVjYuzFUifJ12ToChXFgESKFmuso7WluEaWvMIGREdrMrKQKHfYLOzWF
2B5ZJDqw4o03fU4J/6rw61M1b+rjVpXMjPnzc2A+RgcjTvXv955gfZkwe4lt5wk/
3j8zMVo3+zLrMTAaEeIUM0UCAwEAAQ==
-----END PUBLIC KEY-----`

var defaultPrimaryS3URLs = []string{
	"https://s3.eu-north-1.amazonaws.com/amnezia/",
	"https://storage.googleapis.com/lambda-list/",
	"https://amnzstrg01.blob.core.windows.net/lambda-list/",
	"https://objectstorage.eu-zurich-1.oraclecloud.com/n/zrhfyaq6qxvh/b/lambda-list/o/",
}

var defaultFallbackS3URLs = []string{
	"https://storage.mwsapis.ru/lambda-list/",
	"https://46.8.209.252/lambda-list/",
}

// This list is the successfully decrypted generic production list observed on
// 2026-08-22. Dynamic S3 discovery is tried first; these entries are health-
// checked and serve only as a bootstrap/cache fallback.
var defaultStaticProxyURLs = []string{
	"https://gw-px-le-15436-3w5hsuiikq-ey.a.run.app/",
	"https://sxg5kzkftu.eu-central-1.awsapprunner.com/",
	"https://gw-px-le-4352.kindstone-1374c603.germanywestcentral.azurecontainerapps.io/",
}

// DefaultPrimaryS3URLs returns a caller-owned copy of the official production
// proxy-list storage endpoints.
func DefaultPrimaryS3URLs() []string { return cloneStrings(defaultPrimaryS3URLs) }

// DefaultFallbackS3URLs returns a caller-owned copy of the official fallback
// proxy-list storage endpoints.
func DefaultFallbackS3URLs() []string { return cloneStrings(defaultFallbackS3URLs) }

// DefaultStaticProxyURLs returns a caller-owned copy of the pinned proxy-list
// fallback. The live S3 list can change independently of this module.
func DefaultStaticProxyURLs() []string { return cloneStrings(defaultStaticProxyURLs) }

func cloneStrings(in []string) []string { return append([]string(nil), in...) }
