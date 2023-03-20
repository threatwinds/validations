package validations

const (
	STR         = 1
	IP          = 2
	EMAIL       = 3
	DOMAIN      = 4
	INTEGER     = 5
	CIDR        = 6
	CITY        = 7
	COUNTRY     = 8
	KEYVALUE    = 9
	FLOAT       = 10
	URL         = 11
	MD5         = 12
	HEXADECIMAL = 13
	BASE64      = 14
	HOSTNAME    = 15
	DATE        = 16
	MAC         = 17
	MIME        = 18
	PHONE       = 19
	SHA1        = 20
	SHA224      = 21
	SHA256      = 22
	SHA384      = 23
	SHA512      = 24
	SHA3_224    = 25
	SHA3_256    = 26
	SHA3_384    = 27
	SHA3_512    = 28
	SHA512_224  = 29
	SHA512_256  = 30
	DATETIME    = 31
	UUID        = 32
	BOOLEAN     = 33
	ISTR        = 34
)

type Kind struct {
	Kind         string `json:"kind" example:"object"`
	Description  string `json:"description" example:"Important description about the type"`
	dataType     int
	Example      string `json:"example,omitempty" example:"6ee84de3-3d2d-4a70-a918-d0e590d350e0"`
	Attributes   []Kind `json:"attributes,omitempty"`
	Associations []Kind `json:"associations,omitempty"`
}

var File = Kind{
	Kind:         "file",
	Description:  "Object identifying a file, the value can be a UUID or a SHA3-256 or MD5 checksum",
	dataType:     ISTR,
	Associations: []Kind{Filename, FileData, HashSHA1, HashMD5, HashSHA256, HashSHA3256, FilenamePattern},
}

var FileData = Kind{
	Kind:        "file-data",
	Description: "File or attachment URL",
	dataType:    URL,
	Attributes:  []Kind{SizeInBytes, HashMD5, HashSHA3256, HashSHA1, HashSHA256},
}

var VirusTotalReport = Kind{
	Kind:        "virustotal-report",
	Description: "VirusTotal report",
	dataType:    URL,
	Attributes:  []Kind{Datetime},
}

var Adversary = Kind{
	Kind:        "adversary",
	Description: "Object identifying a threat actor",
	dataType:    ISTR,
}

var ASO = Kind{
	Kind:        "aso",
	Description: "Autonomous System Organization",
	dataType:    ISTR,
}

var ASN = Kind{
	Kind:        "asn",
	Description: "Autonomous System Organization Number",
	dataType:    INTEGER,
}

var Malware = Kind{
	Kind:        "malware",
	Description: "Malware",
	dataType:    ISTR,
	Attributes: []Kind{
		MalwareFamily,
		MalwareType,
	},
}

var Object = Kind{
	Kind:        "object",
	Description: "Generic entity composed of other entities, the value can be a UUID or a SHA3-256 or MD5 checksum",
	dataType:    ISTR,
	Attributes: []Kind{
		Descriptor,
	},
}

var Descriptor = Kind{
	Kind:        "descriptor",
	dataType:    ISTR,
	Description: "The object descriptor",
}

var ABARTN = Kind{
	Kind:        "aba-rtn",
	Description: "ABA routing transit number",
	dataType:    INTEGER,
}

var Latitude = Kind{
	Kind:        "latitude",
	Description: "GPS latitude",
	Example:     "40.741895",
	dataType:    FLOAT,
}

var Longitude = Kind{
	Kind:        "longitude",
	Description: "GPS longitude",
	Example:     "40.741895",
	dataType:    FLOAT,
}

var Country = Kind{
	Kind:        "country",
	Description: "Country name",
	dataType:    COUNTRY,
}

var Cookie = Kind{
	Kind:        "cookie",
	Description: "HTTP cookie as often stored on the user web client. This can include authentication cookie or session cookie",
	dataType:    STR,
	Attributes:  []Kind{Value},
}

var Text = Kind{
	Kind:        "text",
	Description: "Any case insensitive text value",
	dataType:    ISTR,
}

var Value = Kind{
	Kind:        "value",
	Description: "Any case sensitive text value",
	dataType:    STR,
}

var Password = Kind{
	Kind:        "password",
	Description: "Password",
	dataType:    STR,
}

var Airport = Kind{
	Kind:        "airport-name",
	Description: "The airport name",
	dataType:    ISTR,
	Attributes:  []Kind{Country, City},
}

var ProfilePhoto = Kind{
	Kind:        "profile-photo",
	Description: "Profile photo URL",
	dataType:    URL,
}

var AuthentiHash = Kind{
	Kind:        "authentihash",
	Description: "Authenticode executable signature hash",
	dataType:    HEXADECIMAL,
}

var BankAccountNr = Kind{
	Kind:        "bank-account-nr",
	Description: "Bank account number without any routing number",
	dataType:    INTEGER,
	Attributes:  []Kind{BIC, BIN},
}

var BIC = Kind{
	Kind:        "bic",
	Description: "Bank Identifier Code Number also known as SWIFT-BIC, SWIFT code or ISO 9362 code",
	dataType:    ISTR,
}

var BIN = Kind{
	Kind:        "bin",
	Description: "Bank Identification Number",
	dataType:    INTEGER,
}

var BTC = Kind{
	Kind:        "btc",
	Description: "Bitcoin Address",
	dataType:    STR,
}

var CCNumber = Kind{
	Kind:        "cc-number",
	Description: "Credit-Card Number",
	dataType:    INTEGER,
	Attributes:  []Kind{Issuer},
}

var Issuer = Kind{
	Kind:        "issuer",
	Description: "Issuer name",
	dataType:    ISTR,
}

var CDHash = Kind{
	Kind:        "cdhash",
	Description: "An Apple Code Directory Hash, identifying a code-signed Mach-O executable file",
	dataType:    HEXADECIMAL,
}

var CertificateFingerprint = Kind{
	Kind:        "certificate-fingerprint",
	Description: "The fingerprint of a SSL/TLS certificate",
	dataType:    HEXADECIMAL,
}

var ChromeExtension = Kind{
	Kind:        "chrome-extension-id",
	Description: "Chrome extension ID",
	dataType:    STR,
}

var Subnet = Kind{
	Kind:        "cidr",
	Description: "A public network segment like 140.40.24.0/24",
	dataType:    CIDR,
	Attributes:  []Kind{Country, City, Latitude, Longitude, ASN, ASO},
}

var CPE = Kind{
	Kind:        "cpe",
	Description: "Common Platform Enumeration. Structured naming scheme for information technology systems, software, and packages",
	dataType:    ISTR,
}

var CVE = Kind{
	Kind:        "cve",
	Description: "",
	dataType:    ISTR,
}

var Dash = Kind{
	Kind:        "dash",
	Description: "Dash address",
	dataType:    STR,
}

var DKIM = Kind{
	Kind:        "dkim",
	Description: "DKIM public key",
	dataType:    STR,
}

var DKIMSignature = Kind{
	Kind:        "dkim-signature",
	Description: "DKIM signature",
	dataType:    STR,
}

var Domain = Kind{
	Kind:        "domain",
	Description: "Internet domain like example.com",
	dataType:    DOMAIN,
	Attributes:  []Kind{WhoIsRegistrant, WhoIsRegistrar},
}

var Email = Kind{
	Kind:        "email",
	Description: "Email Message ID",
	dataType:    STR,
	Example:     "950124.162336@example.com",
	Attributes:  []Kind{EmailBody, EmailDisplayName, EmailHeader, EmailAddress, EmailSubject},
}

var City = Kind{
	Kind:        "city",
	Description: "City name",
	dataType:    CITY,
}

var IssuingCountry = Kind{
	Kind:        "issuing-country",
	Description: "Issuing country name",
	dataType:    COUNTRY,
}

var EmailAddress = Kind{
	Kind:        "email-address",
	Description: "Sender email address",
	dataType:    EMAIL,
}

var EmailBody = Kind{
	Kind:        "email-body",
	Description: "Email body",
	dataType:    ISTR,
}

var EmailDisplayName = Kind{
	Kind:        "email-display-name",
	Description: "Sender display name",
	dataType:    ISTR,
}

var EmailHeader = Kind{
	Kind:        "email-header",
	Description: "Email header (all headers)",
	dataType:    STR,
}

var EmailMimeBoundary = Kind{
	Kind:        "email-mime-boundary",
	Description: "MIME boundaries are strings of 7-bit US-ASCII text that define the boundaries between message parts in a MIME message. MIME boundaries are declared in a Content-Type message header for any message that encapsulates more than one message part and in part headers for those parts that encapsulate nested parts.",
	dataType:    STR,
}

var EmailSubject = Kind{
	Kind:        "email-subject",
	Description: "The subject of the email",
	dataType:    ISTR,
}

var EmailThreadIndex = Kind{
	Kind:        "email-thread-index",
	Description: "The email thread index",
	dataType:    BASE64,
}

var EmailXMailer = Kind{
	Kind:        "email-x-mailer",
	Description: "Email x-mailer header",
	dataType:    ISTR,
}

var EPPN = Kind{
	Kind:        "eppn",
	Description: "The NetId of the person for the purposes of inter-institutional authentication. Should be stored in the form of user@univ.edu, where univ.edu is the name of the local security domain",
	dataType:    EMAIL,
}

var FacebookID = Kind{
	Kind:        "facebook-id",
	Description: "Facebook profile",
	dataType:    URL,
}

var FFN = Kind{
	Kind:        "ffn",
	Description: "The frequent flyer number of a passanger",
	dataType:    STR,
}

var Filename = Kind{
	Kind:        "filename",
	Description: "A filename or email attachment name",
	dataType:    ISTR,
}

var SizeInBytes = Kind{
	Kind:        "size-in-bytes",
	Description: "The size in bytes of an element",
	dataType:    FLOAT,
}

var FilenamePattern = Kind{
	Kind:        "filename-pattern",
	Description: "A pattern in the name of a file",
	dataType:    STR,
}

var Flight = Kind{
	Kind:        "flight",
	Description: "A flight number",
	dataType:    STR,
}

var GENE = Kind{
	Kind:        "gene",
	Description: "Go Evtx sigNature Engine",
	dataType:    STR,
}

var GitHubOrganization = Kind{
	Kind:        "github-organization",
	Description: "Github organization",
	dataType:    URL,
}

var GitHubRepository = Kind{
	Kind:        "github-repository",
	Description: "Github repository",
	dataType:    URL,
}

var GitHubUser = Kind{
	Kind:        "github-user",
	Description: "Github user",
	dataType:    URL,
}

var Link = Kind{
	Kind:        "link",
	Description: "External link for reference",
	dataType:    URL,
}

var Datetime = Kind{
	Kind:        "datetime",
	Description: "Time with nanoseconds in the format 2006-01-02T15:04:05.999999999Z07:00",
	dataType:    DATETIME,
}

var Date = Kind{
	Kind:        "date",
	Description: "Date in format 2006-01-02",
	dataType:    DATE,
}

var MalwareSample = Kind{
	Kind:        "malware-sample",
	Description: "Malware Sample URL",
	dataType:    URL,
	Attributes:  []Kind{Malware, File},
}

var Group = Kind{
	Kind:        "group",
	Description: "Adversaries group",
	dataType:    ISTR,
}

var HaSSHMD5 = Kind{
	Kind:        "hassh-md5",
	Description: "Network fingerprinting standard which can be used to identify specific Client SSH implementations. The fingerprints can be easily stored, searched and shared in the form of an MD5 fingerprint",
	dataType:    MD5,
}

var HaSSHServerMD5 = Kind{
	Kind:        "hasshserver-md5",
	Description: "Network fingerprinting standard which can be used to identify specific Server SSH implementations. The fingerprints can be easily stored, searched and shared in the form of an MD5 fingerprint",
	dataType:    MD5,
}

var Hex = Kind{
	Kind:        "hex",
	Description: "A value in hexadecimal",
	dataType:    HEXADECIMAL,
}

var Base64 = Kind{
	Kind:        "base64",
	Description: "A value in BASE64 format",
	dataType:    BASE64,
}

var Hostname = Kind{
	Kind:        "hostname",
	Description: "A full host/dnsname of an attacker",
	dataType:    HOSTNAME,
}

var IBAN = Kind{
	Kind:        "iban",
	Description: "International Bank Account Number",
	dataType:    ISTR,
}

var IDNumber = Kind{
	Kind:        "id-number",
	Description: "It can be an ID card, residence permit, etc.",
	dataType:    STR,
	Attributes:  []Kind{Issuer, IssuingCountry, Date},
}

var IPAddr = Kind{
	Kind:        "ip",
	Description: "IP Address like 8.8.8.8",
	dataType:    IP,
	Attributes:  []Kind{Subnet},
}

var JA3Fingerprint = Kind{
	Kind:        "ja3-fingerprint-md5",
	Description: "JA3 is a method for creating SSL/TLS client fingerprints that should be easy to produce on any platform and can be easily shared for threat intelligence",
	dataType:    MD5,
}

var JabberID = Kind{
	Kind:        "jabber-id",
	Description: "Jabber ID",
	dataType:    EMAIL,
}

var JARMFingerprint = Kind{
	Kind:        "jarm-fingerprint",
	Description: "JARM is a method for creating SSL/TLS server fingerprints",
	dataType:    HEXADECIMAL,
}

var MACAddr = Kind{
	Kind:        "mac-address",
	Description: "Network interface hardware address",
	dataType:    MAC,
}

var MalwareFamily = Kind{
	Kind:        "malware-family",
	Description: "Malware family",
	dataType:    ISTR,
}

var MalwareType = Kind{
	Kind:        "malware-type",
	Description: "Malware type",
	dataType:    ISTR,
}

var HashMD5 = Kind{
	Kind:        "md5",
	Description: "Hash MD5",
	dataType:    MD5,
}

var MimeType = Kind{
	Kind:        "mime-type",
	Description: "A media type (also MIME type and content type) is a two-part identifier",
	dataType:    MIME,
}

var MobileAppID = Kind{
	Kind:        "mobile-app-id",
	Description: "The ID of a mobile application",
	dataType:    STR,
}

var Passport = Kind{
	Kind:        "passport",
	Description: "Passport number",
	dataType:    STR,
	Attributes:  []Kind{IssuingCountry, Issuer, Date},
}

var Path = Kind{
	Kind:        "path",
	Description: "Path to a file, folder or process, also a HTTP request path",
	dataType:    STR,
}

var PatternInFile = Kind{
	Kind:        "pattern-in-file",
	Description: "Pattern inside a file",
	dataType:    STR,
}

var PatternInMemory = Kind{
	Kind:        "pattern-in-memory",
	Description: "Pattern in memory",
	dataType:    STR,
}

var PatternInTraffic = Kind{
	Kind:        "pattern-in-traffic",
	Description: "Pattern in traffic",
	dataType:    STR,
}

var PGPPrivateKey = Kind{
	Kind:        "pgp-private-key",
	Description: "PGP private key",
	dataType:    STR,
}

var PGPPublicKey = Kind{
	Kind:        "pgp-public-key",
	Description: "PGP public key",
	dataType:    STR,
}

var Phone = Kind{
	Kind:        "phone",
	Description: "Phone number",
	dataType:    PHONE,
}

var PNR = Kind{
	Kind:        "pnr",
	Description: "The Passenger Name Record Locator is a key under which the reservation for a trip is stored in the system. The PNR contains, among other data, the name, flight segments and address of the passenger. It is defined by a combination of five or six letters and numbers",
	dataType:    STR,
}

var Process = Kind{
	Kind:        "process",
	Description: "A running process",
	dataType:    ISTR,
	Attributes:  []Kind{ProcessState},
}

var ProcessState = Kind{
	Kind:        "process-state",
	Description: "State of a process",
	dataType:    ISTR,
}

var PRTN = Kind{
	Kind:        "prtn",
	Description: "Premium-rate telephone number",
	dataType:    ISTR,
}

var Redress = Kind{
	Kind:        "redress-number",
	Description: "The Redress Control Number is the record identifier for people who apply for redress through the DHS Travel Redress Inquiry Program (DHS TRIP). DHS TRIP is for travelers who have been repeatedly identified for additional screening and who want to file an inquiry to have erroneous information corrected in DHS systems",
	dataType:    STR,
}

var RegKey = Kind{
	Kind:        "regkey",
	Description: "Registry key",
	dataType:    ISTR,
}

var HashSHA1 = Kind{
	Kind:        "sha1",
	Description: "Hash SHA1",
	dataType:    SHA1,
}

var HashSHA224 = Kind{
	Kind:        "sha224",
	Description: "Hash SHA224",
	dataType:    SHA224,
}

var HashSHA256 = Kind{
	Kind:        "sha256",
	Description: "Hash SHA256",
	dataType:    SHA256,
}

var HashSHA384 = Kind{
	Kind:        "sha384",
	Description: "Hash SHA384",
	dataType:    SHA384,
}

var HashSHA512 = Kind{
	Kind:        "sha512",
	Description: "Hash SHA512",
	dataType:    SHA512,
}

var HashSHA3224 = Kind{
	Kind:        "sha3-224",
	Description: "Hash SHA3-224",
	dataType:    SHA3_224,
}

var HashSHA3256 = Kind{
	Kind:        "sha3-256",
	Description: "Hash SHA3-256",
	dataType:    SHA3_256,
}

var HashSHA3384 = Kind{
	Kind:        "sha3-384",
	Description: "Hash SHA3-384",
	dataType:    SHA3_384,
}

var HashSHA3512 = Kind{
	Kind:        "sha3-512",
	Description: "Hash SHA3-512",
	dataType:    SHA3_512,
}

var HashSHA512224 = Kind{
	Kind:        "sha512-224",
	Description: "Hash SHA512-224",
	dataType:    SHA512_224,
}

var HashSHA512256 = Kind{
	Kind:        "sha512-256",
	Description: "Hash SHA512-256",
	dataType:    SHA512_256,
}

var SSHFingerprint = Kind{
	Kind:        "ssh-fingerprint",
	Description: "A fingerprint of SSH key material",
	dataType:    STR,
}

var SSR = Kind{
	Kind:        "ssr",
	Description: "A Special Service Request is a function to an airline to provide a particular facility for A Passenger or passengers",
	dataType:    STR,
}

var Category = Kind{
	Kind:        "category",
	Description: "A category",
	dataType:    ISTR,
}

var Threat = Kind{
	Kind:        "threat",
	Description: "A cybersecurity threat",
	dataType:    ISTR,
}

var TikTokID = Kind{
	Kind:        "tiktok-id",
	Description: "TikTok user ID",
	dataType:    URL,
}

var TwitterID = Kind{
	Kind:        "twitter-id",
	Description: "A Twitter user ID",
	dataType:    URL,
}

var URI = Kind{
	Kind:        "url",
	Description: "URL",
	dataType:    URL,
}

var Username = Kind{
	Kind:        "username",
	Description: "Username",
	dataType:    ISTR,
}

var Visa = Kind{
	Kind:        "visa",
	Description: "Visa number",
	dataType:    STR,
}

var WhoIsRegistrant = Kind{
	Kind:        "whois-registrant",
	Description: "Who is registrant",
	dataType:    ISTR,
}

var WhoIsRegistrar = Kind{
	Kind:        "whois-registrar",
	Description: "whois-registrar",
	dataType:    ISTR,
}

var WindowsScheduledTask = Kind{
	Kind:        "windows-scheduled-task",
	Description: "A Windows scheduled task",
	dataType:    ISTR,
}

var WindowsServiceDisplayName = Kind{
	Kind:        "windows-service-displayname",
	Description: "A windows service’s displayname, not to be confused with the windows-service-name. This is the name that applications will generally display as the service’s name in applications",
	dataType:    ISTR,
}

var WindowsServiceName = Kind{
	Kind:        "windows-service-name",
	Description: "A windows service name. This is the name used internally by windows. Not to be confused with the windows-service-displayname",
	dataType:    ISTR,
}

var XMR = Kind{
	Kind:        "xmr",
	Description: "Monero address",
	dataType:    STR,
}

var X509MD5 = Kind{
	Kind:        "x509-fingerprint-md5",
	Description: "X509 fingerprint in MD5",
	dataType:    MD5,
}

var X509SHA1 = Kind{
	Kind:        "x509-fingerprint-sha1",
	Description: "X509 fingerprint in SHA1",
	dataType:    SHA1,
}

var X509SHA256 = Kind{
	Kind:        "x509-fingerprint-sha256",
	Description: "X509 fingerprint in SHA256",
	dataType:    SHA256,
}

var YaraRule = Kind{
	Kind:        "yara-rule",
	Description: "Yara rule",
	dataType:    STR,
}

var SuricataRule = Kind{
	Kind:        "suricata-rule",
	Description: "Suricata rule",
	dataType:    STR,
}

var OSSECRule = Kind{
	Kind:        "ossec-rule",
	Description: "OSSEC rule",
	dataType:    STR,
}

var ElasticRule = Kind{
	Kind:        "elastic-rule",
	Description: "Elasticsearch rule",
	dataType:    STR,
}

var Kinds = []Kind{
	File,
	FileData,
	VirusTotalReport,
	Adversary,
	ASO,
	ASN,
	Malware,
	MalwareFamily,
	MalwareType,
	MalwareSample,
	Object,
	Descriptor,
	ABARTN,
	Latitude,
	Longitude,
	Country,
	Cookie,
	Text,
	Value,
	Issuer,
	Password,
	Airport,
	ProfilePhoto,
	AuthentiHash,
	BankAccountNr,
	BIC,
	BIN,
	BTC,
	CCNumber,
	CDHash,
	CertificateFingerprint,
	ChromeExtension,
	Subnet,
	CPE,
	CVE,
	Dash,
	DKIM,
	DKIMSignature,
	Domain,
	Email,
	City,
	IssuingCountry,
	EmailAddress,
	EmailBody,
	EmailDisplayName,
	EmailHeader,
	EmailMimeBoundary,
	EmailSubject,
	EmailThreadIndex,
	EmailXMailer,
	Email,
	EPPN,
	FacebookID,
	FFN,
	Filename,
	SizeInBytes,
	FilenamePattern,
	Flight,
	GENE,
	GitHubOrganization,
	GitHubRepository,
	GitHubUser,
	Link,
	Datetime,
	Date,
	Group,
	HaSSHMD5,
	HaSSHServerMD5,
	Hex,
	Base64,
	Hostname,
	IBAN,
	IDNumber,
	IPAddr,
	JA3Fingerprint,
	JabberID,
	JARMFingerprint,
	MACAddr,
	HashMD5,
	MimeType,
	MobileAppID,
	Passport,
	Path,
	PatternInFile,
	PatternInMemory,
	PatternInTraffic,
	PGPPrivateKey,
	PGPPublicKey,
	Phone,
	PNR,
	Process,
	ProcessState,
	PRTN,
	Redress,
	RegKey,
	HashSHA1,
	HashSHA224,
	HashSHA256,
	HashSHA384,
	HashSHA512,
	HashSHA3224,
	HashSHA3256,
	HashSHA3384,
	HashSHA3512,
	HashSHA512224,
	HashSHA512256,
	SSHFingerprint,
	SSR,
	Category,
	Threat,
	TikTokID,
	TwitterID,
	URI,
	Username,
	Visa,
	WhoIsRegistrant,
	WhoIsRegistrar,
	WindowsScheduledTask,
	WindowsServiceDisplayName,
	WindowsServiceName,
	XMR,
	X509MD5,
	X509SHA1,
	X509SHA256,
	YaraRule,
	SuricataRule,
	OSSECRule,
	ElasticRule,
}
