package validations

const (
	STR         = "Case-sensitive string"
	IP          = "IP"
	EMAIL       = "Email"
	DOMAIN      = "Domain"
	INTEGER     = "Integer"
	CIDR        = "CIDR"
	CITY        = "City"
	COUNTRY     = "Country"
	FLOAT       = "Float"
	URL         = "URL"
	MD5         = "MD5"
	HEXADECIMAL = "Hexadecimal"
	BASE64      = "BASE64"
	HOSTNAME    = "Hostname"
	DATE        = "Date"
	MAC         = "MAC"
	MIME        = "MIME type"
	PHONE       = "Phone"
	SHA1        = "SHA-1"
	SHA224      = "SHA-224"
	SHA256      = "SHA-256"
	SHA384      = "SHA-384"
	SHA512      = "SHA-512"
	SHA3_224    = "SHA3-224"
	SHA3_256    = "SHA3-256"
	SHA3_384    = "SHA3-384"
	SHA3_512    = "SHA3-512"
	SHA512_224  = "SHA512-224"
	SHA512_256  = "SHA512-256"
	DATETIME    = "Datetime"
	UUID        = "UUID"
	BOOLEAN     = "Boolean"
	ISTR        = "String"
)

type Kind struct {
	Kind         string `json:"kind" example:"object"`
	Description  string `json:"description" example:"Important description about the type"`
	DataType     string
	Example      interface{} `json:"example,omitempty" example:"6ee84de3-3d2d-4a70-a918-d0e590d350e0"`
	Attributes   []Kind `json:"attributes,omitempty"`
	Associations []Kind `json:"associations,omitempty"`
}

var File = Kind{
	Kind:         "file",
	Description:  "Object identifying a file, the value can be a UUID or a SHA3-256 or MD5 checksum",
	DataType:     ISTR,
	Associations: []Kind{Filename, FileData, HashSHA1, HashMD5, HashSHA256, HashSHA3256, FilenamePattern},
}

var FileData = Kind{
	Kind:        "file-data",
	Description: "File or attachment URL",
	DataType:    URL,
	Attributes:  []Kind{SizeInBytes, HashMD5, HashSHA3256, HashSHA1, HashSHA256},
}

var VirusTotalReport = Kind{
	Kind:        "virustotal-report",
	Description: "VirusTotal report",
	DataType:    URL,
	Attributes:  []Kind{Datetime},
}

var Adversary = Kind{
	Kind:        "adversary",
	Description: "Object identifying a threat actor",
	DataType:    ISTR,
}

var ASO = Kind{
	Kind:        "aso",
	Description: "Autonomous System Organization",
	DataType:    ISTR,
}

var ASN = Kind{
	Kind:        "asn",
	Description: "Autonomous System Organization Number",
	DataType:    INTEGER,
}

var Malware = Kind{
	Kind:        "malware",
	Description: "Malware",
	DataType:    ISTR,
	Attributes: []Kind{
		MalwareFamily,
		MalwareType,
	},
}

var Object = Kind{
	Kind:        "object",
	Description: "Generic entity composed of other entities, the value can be a UUID or a SHA3-256 or MD5 checksum",
	DataType:    ISTR,
	Attributes: []Kind{
		Descriptor,
	},
}

var Descriptor = Kind{
	Kind:        "descriptor",
	DataType:    ISTR,
	Description: "The object descriptor",
}

var ABARTN = Kind{
	Kind:        "aba-rtn",
	Description: "ABA routing transit number",
	DataType:    INTEGER,
}

var Latitude = Kind{
	Kind:        "latitude",
	Description: "GPS latitude",
	Example:     "40.741895",
	DataType:    FLOAT,
}

var Longitude = Kind{
	Kind:        "longitude",
	Description: "GPS longitude",
	Example:     "40.741895",
	DataType:    FLOAT,
}

var Country = Kind{
	Kind:        "country",
	Description: "Country name",
	DataType:    COUNTRY,
}

var Cookie = Kind{
	Kind:        "cookie",
	Description: "HTTP cookie as often stored on the user web client. This can include authentication cookie or session cookie",
	DataType:    STR,
	Attributes:  []Kind{Value},
}

var Text = Kind{
	Kind:        "text",
	Description: "Any case insensitive text value",
	DataType:    ISTR,
}

var Value = Kind{
	Kind:        "value",
	Description: "Any case sensitive text value",
	DataType:    STR,
}

var Password = Kind{
	Kind:        "password",
	Description: "Password",
	DataType:    STR,
}

var Airport = Kind{
	Kind:        "airport-name",
	Description: "The airport name",
	DataType:    ISTR,
	Attributes:  []Kind{Country, City},
}

var ProfilePhoto = Kind{
	Kind:        "profile-photo",
	Description: "Profile photo URL",
	DataType:    URL,
}

var AuthentiHash = Kind{
	Kind:        "authentihash",
	Description: "Authenticode executable signature hash",
	DataType:    HEXADECIMAL,
}

var BankAccountNr = Kind{
	Kind:        "bank-account-nr",
	Description: "Bank account number without any routing number",
	DataType:    INTEGER,
	Attributes:  []Kind{BIC, BIN},
}

var BIC = Kind{
	Kind:        "bic",
	Description: "Bank Identifier Code Number also known as SWIFT-BIC, SWIFT code or ISO 9362 code",
	DataType:    ISTR,
}

var BIN = Kind{
	Kind:        "bin",
	Description: "Bank Identification Number",
	DataType:    INTEGER,
}

var BTC = Kind{
	Kind:        "btc",
	Description: "Bitcoin Address",
	DataType:    STR,
}

var CCNumber = Kind{
	Kind:        "cc-number",
	Description: "Credit-Card Number",
	DataType:    INTEGER,
	Attributes:  []Kind{Issuer},
}

var Issuer = Kind{
	Kind:        "issuer",
	Description: "Issuer name",
	DataType:    ISTR,
}

var CDHash = Kind{
	Kind:        "cdhash",
	Description: "An Apple Code Directory Hash, identifying a code-signed Mach-O executable file",
	DataType:    HEXADECIMAL,
}

var CertificateFingerprint = Kind{
	Kind:        "certificate-fingerprint",
	Description: "The fingerprint of a SSL/TLS certificate",
	DataType:    HEXADECIMAL,
}

var ChromeExtension = Kind{
	Kind:        "chrome-extension-id",
	Description: "Chrome extension ID",
	DataType:    STR,
}

var Subnet = Kind{
	Kind:        "cidr",
	Description: "A public network segment like 140.40.24.0/24",
	DataType:    CIDR,
	Attributes:  []Kind{Country, City, Latitude, Longitude, ASN, ASO},
}

var CPE = Kind{
	Kind:        "cpe",
	Description: "Common Platform Enumeration. Structured naming scheme for information technology systems, software, and packages",
	DataType:    ISTR,
}

var CVE = Kind{
	Kind:        "cve",
	Description: "",
	DataType:    ISTR,
}

var Dash = Kind{
	Kind:        "dash",
	Description: "Dash address",
	DataType:    STR,
}

var DKIM = Kind{
	Kind:        "dkim",
	Description: "DKIM public key",
	DataType:    STR,
}

var DKIMSignature = Kind{
	Kind:        "dkim-signature",
	Description: "DKIM signature",
	DataType:    STR,
}

var Domain = Kind{
	Kind:        "domain",
	Description: "Internet domain like example.com",
	DataType:    DOMAIN,
	Attributes:  []Kind{WhoIsRegistrant, WhoIsRegistrar},
}

var Email = Kind{
	Kind:        "email",
	Description: "Email Message ID",
	DataType:    STR,
	Example:     "950124.162336@example.com",
	Attributes:  []Kind{EmailBody, EmailDisplayName, EmailHeader, EmailAddress, EmailSubject},
}

var City = Kind{
	Kind:        "city",
	Description: "City name",
	DataType:    CITY,
}

var IssuingCountry = Kind{
	Kind:        "issuing-country",
	Description: "Issuing country name",
	DataType:    COUNTRY,
}

var EmailAddress = Kind{
	Kind:        "email-address",
	Description: "Sender email address",
	DataType:    EMAIL,
}

var EmailBody = Kind{
	Kind:        "email-body",
	Description: "Email body",
	DataType:    ISTR,
}

var EmailDisplayName = Kind{
	Kind:        "email-display-name",
	Description: "Sender display name",
	DataType:    ISTR,
}

var EmailHeader = Kind{
	Kind:        "email-header",
	Description: "Email header (all headers)",
	DataType:    STR,
}

var EmailMimeBoundary = Kind{
	Kind:        "email-mime-boundary",
	Description: "MIME boundaries are strings of 7-bit US-ASCII text that define the boundaries between message parts in a MIME message. MIME boundaries are declared in a Content-Type message header for any message that encapsulates more than one message part and in part headers for those parts that encapsulate nested parts.",
	DataType:    STR,
}

var EmailSubject = Kind{
	Kind:        "email-subject",
	Description: "The subject of the email",
	DataType:    ISTR,
}

var EmailThreadIndex = Kind{
	Kind:        "email-thread-index",
	Description: "The email thread index",
	DataType:    BASE64,
}

var EmailXMailer = Kind{
	Kind:        "email-x-mailer",
	Description: "Email x-mailer header",
	DataType:    ISTR,
}

var EPPN = Kind{
	Kind:        "eppn",
	Description: "The NetId of the person for the purposes of inter-institutional authentication. Should be stored in the form of user@univ.edu, where univ.edu is the name of the local security domain",
	DataType:    EMAIL,
}

var FacebookID = Kind{
	Kind:        "facebook-id",
	Description: "Facebook profile",
	DataType:    URL,
}

var FFN = Kind{
	Kind:        "ffn",
	Description: "The frequent flyer number of a passanger",
	DataType:    STR,
}

var Filename = Kind{
	Kind:        "filename",
	Description: "A filename or email attachment name",
	DataType:    ISTR,
}

var SizeInBytes = Kind{
	Kind:        "size-in-bytes",
	Description: "The size in bytes of an element",
	DataType:    FLOAT,
}

var FilenamePattern = Kind{
	Kind:        "filename-pattern",
	Description: "A pattern in the name of a file",
	DataType:    STR,
}

var Flight = Kind{
	Kind:        "flight",
	Description: "A flight number",
	DataType:    STR,
}

var GENE = Kind{
	Kind:        "gene",
	Description: "Go Evtx sigNature Engine",
	DataType:    STR,
}

var GitHubOrganization = Kind{
	Kind:        "github-organization",
	Description: "Github organization",
	DataType:    URL,
}

var GitHubRepository = Kind{
	Kind:        "github-repository",
	Description: "Github repository",
	DataType:    URL,
}

var GitHubUser = Kind{
	Kind:        "github-user",
	Description: "Github user",
	DataType:    URL,
}

var Link = Kind{
	Kind:        "link",
	Description: "External link for reference",
	DataType:    URL,
}

var Datetime = Kind{
	Kind:        "datetime",
	Description: "Time with nanoseconds in the format 2006-01-02T15:04:05.999999999Z07:00",
	DataType:    DATETIME,
}

var Date = Kind{
	Kind:        "date",
	Description: "Date in format 2006-01-02",
	DataType:    DATE,
}

var MalwareSample = Kind{
	Kind:        "malware-sample",
	Description: "Malware Sample URL",
	DataType:    URL,
	Attributes:  []Kind{Malware, File},
}

var Group = Kind{
	Kind:        "group",
	Description: "Adversaries group",
	DataType:    ISTR,
}

var HaSSHMD5 = Kind{
	Kind:        "hassh-md5",
	Description: "Network fingerprinting standard which can be used to identify specific Client SSH implementations. The fingerprints can be easily stored, searched and shared in the form of an MD5 fingerprint",
	DataType:    MD5,
}

var HaSSHServerMD5 = Kind{
	Kind:        "hasshserver-md5",
	Description: "Network fingerprinting standard which can be used to identify specific Server SSH implementations. The fingerprints can be easily stored, searched and shared in the form of an MD5 fingerprint",
	DataType:    MD5,
}

var Hex = Kind{
	Kind:        "hex",
	Description: "A value in hexadecimal",
	DataType:    HEXADECIMAL,
}

var Base64 = Kind{
	Kind:        "base64",
	Description: "A value in BASE64 format",
	DataType:    BASE64,
}

var Hostname = Kind{
	Kind:        "hostname",
	Description: "A full host/dnsname of an attacker",
	DataType:    HOSTNAME,
}

var IBAN = Kind{
	Kind:        "iban",
	Description: "International Bank Account Number",
	DataType:    ISTR,
}

var IDNumber = Kind{
	Kind:        "id-number",
	Description: "It can be an ID card, residence permit, etc.",
	DataType:    STR,
	Attributes:  []Kind{Issuer, IssuingCountry, Date},
}

var IPAddr = Kind{
	Kind:        "ip",
	Description: "IP Address like 8.8.8.8",
	DataType:    IP,
	Attributes:  []Kind{Subnet},
}

var JA3Fingerprint = Kind{
	Kind:        "ja3-fingerprint-md5",
	Description: "JA3 is a method for creating SSL/TLS client fingerprints that should be easy to produce on any platform and can be easily shared for threat intelligence",
	DataType:    MD5,
}

var JabberID = Kind{
	Kind:        "jabber-id",
	Description: "Jabber ID",
	DataType:    EMAIL,
}

var JARMFingerprint = Kind{
	Kind:        "jarm-fingerprint",
	Description: "JARM is a method for creating SSL/TLS server fingerprints",
	DataType:    HEXADECIMAL,
}

var MACAddr = Kind{
	Kind:        "mac-address",
	Description: "Network interface hardware address",
	DataType:    MAC,
}

var MalwareFamily = Kind{
	Kind:        "malware-family",
	Description: "Malware family",
	DataType:    ISTR,
}

var MalwareType = Kind{
	Kind:        "malware-type",
	Description: "Malware type",
	DataType:    ISTR,
}

var HashMD5 = Kind{
	Kind:        "md5",
	Description: "Hash MD5",
	DataType:    MD5,
}

var MimeType = Kind{
	Kind:        "mime-type",
	Description: "A media type (also MIME type and content type) is a two-part identifier",
	DataType:    MIME,
}

var MobileAppID = Kind{
	Kind:        "mobile-app-id",
	Description: "The ID of a mobile application",
	DataType:    STR,
}

var Passport = Kind{
	Kind:        "passport",
	Description: "Passport number",
	DataType:    STR,
	Attributes:  []Kind{IssuingCountry, Issuer, Date},
}

var Path = Kind{
	Kind:        "path",
	Description: "Path to a file, folder or process, also a HTTP request path",
	DataType:    STR,
}

var PatternInFile = Kind{
	Kind:        "pattern-in-file",
	Description: "Pattern inside a file",
	DataType:    STR,
}

var PatternInMemory = Kind{
	Kind:        "pattern-in-memory",
	Description: "Pattern in memory",
	DataType:    STR,
}

var PatternInTraffic = Kind{
	Kind:        "pattern-in-traffic",
	Description: "Pattern in traffic",
	DataType:    STR,
}

var PGPPrivateKey = Kind{
	Kind:        "pgp-private-key",
	Description: "PGP private key",
	DataType:    STR,
}

var PGPPublicKey = Kind{
	Kind:        "pgp-public-key",
	Description: "PGP public key",
	DataType:    STR,
}

var Phone = Kind{
	Kind:        "phone",
	Description: "Phone number",
	DataType:    PHONE,
}

var PNR = Kind{
	Kind:        "pnr",
	Description: "The Passenger Name Record Locator is a key under which the reservation for a trip is stored in the system. The PNR contains, among other data, the name, flight segments and address of the passenger. It is defined by a combination of five or six letters and numbers",
	DataType:    STR,
}

var Process = Kind{
	Kind:        "process",
	Description: "A running process",
	DataType:    ISTR,
	Attributes:  []Kind{ProcessState},
}

var ProcessState = Kind{
	Kind:        "process-state",
	Description: "State of a process",
	DataType:    ISTR,
}

var PRTN = Kind{
	Kind:        "prtn",
	Description: "Premium-rate telephone number",
	DataType:    ISTR,
}

var Redress = Kind{
	Kind:        "redress-number",
	Description: "The Redress Control Number is the record identifier for people who apply for redress through the DHS Travel Redress Inquiry Program (DHS TRIP). DHS TRIP is for travelers who have been repeatedly identified for additional screening and who want to file an inquiry to have erroneous information corrected in DHS systems",
	DataType:    STR,
}

var RegKey = Kind{
	Kind:        "regkey",
	Description: "Registry key",
	DataType:    ISTR,
}

var HashSHA1 = Kind{
	Kind:        "sha1",
	Description: "Hash SHA1",
	DataType:    SHA1,
}

var HashSHA224 = Kind{
	Kind:        "sha224",
	Description: "Hash SHA224",
	DataType:    SHA224,
}

var HashSHA256 = Kind{
	Kind:        "sha256",
	Description: "Hash SHA256",
	DataType:    SHA256,
}

var HashSHA384 = Kind{
	Kind:        "sha384",
	Description: "Hash SHA384",
	DataType:    SHA384,
}

var HashSHA512 = Kind{
	Kind:        "sha512",
	Description: "Hash SHA512",
	DataType:    SHA512,
}

var HashSHA3224 = Kind{
	Kind:        "sha3-224",
	Description: "Hash SHA3-224",
	DataType:    SHA3_224,
}

var HashSHA3256 = Kind{
	Kind:        "sha3-256",
	Description: "Hash SHA3-256",
	DataType:    SHA3_256,
}

var HashSHA3384 = Kind{
	Kind:        "sha3-384",
	Description: "Hash SHA3-384",
	DataType:    SHA3_384,
}

var HashSHA3512 = Kind{
	Kind:        "sha3-512",
	Description: "Hash SHA3-512",
	DataType:    SHA3_512,
}

var HashSHA512224 = Kind{
	Kind:        "sha512-224",
	Description: "Hash SHA512-224",
	DataType:    SHA512_224,
}

var HashSHA512256 = Kind{
	Kind:        "sha512-256",
	Description: "Hash SHA512-256",
	DataType:    SHA512_256,
}

var SSHFingerprint = Kind{
	Kind:        "ssh-fingerprint",
	Description: "A fingerprint of SSH key material",
	DataType:    STR,
}

var SSR = Kind{
	Kind:        "ssr",
	Description: "A Special Service Request is a function to an airline to provide a particular facility for A Passenger or passengers",
	DataType:    STR,
}

var Category = Kind{
	Kind:        "category",
	Description: "A category",
	DataType:    ISTR,
}

var Threat = Kind{
	Kind:        "threat",
	Description: "A cybersecurity threat",
	DataType:    ISTR,
}

var TikTokID = Kind{
	Kind:        "tiktok-id",
	Description: "TikTok user ID",
	DataType:    URL,
}

var TwitterID = Kind{
	Kind:        "twitter-id",
	Description: "A Twitter user ID",
	DataType:    URL,
}

var URI = Kind{
	Kind:        "url",
	Description: "URL",
	DataType:    URL,
}

var Username = Kind{
	Kind:        "username",
	Description: "Username",
	DataType:    ISTR,
}

var Visa = Kind{
	Kind:        "visa",
	Description: "Visa number",
	DataType:    STR,
}

var WhoIsRegistrant = Kind{
	Kind:        "whois-registrant",
	Description: "Who is registrant",
	DataType:    ISTR,
}

var WhoIsRegistrar = Kind{
	Kind:        "whois-registrar",
	Description: "whois-registrar",
	DataType:    ISTR,
}

var WindowsScheduledTask = Kind{
	Kind:        "windows-scheduled-task",
	Description: "A Windows scheduled task",
	DataType:    ISTR,
}

var WindowsServiceDisplayName = Kind{
	Kind:        "windows-service-displayname",
	Description: "A windows service’s displayname, not to be confused with the windows-service-name. This is the name that applications will generally display as the service’s name in applications",
	DataType:    ISTR,
}

var WindowsServiceName = Kind{
	Kind:        "windows-service-name",
	Description: "A windows service name. This is the name used internally by windows. Not to be confused with the windows-service-displayname",
	DataType:    ISTR,
}

var XMR = Kind{
	Kind:        "xmr",
	Description: "Monero address",
	DataType:    STR,
}

var X509MD5 = Kind{
	Kind:        "x509-fingerprint-md5",
	Description: "X509 fingerprint in MD5",
	DataType:    MD5,
}

var X509SHA1 = Kind{
	Kind:        "x509-fingerprint-sha1",
	Description: "X509 fingerprint in SHA1",
	DataType:    SHA1,
}

var X509SHA256 = Kind{
	Kind:        "x509-fingerprint-sha256",
	Description: "X509 fingerprint in SHA256",
	DataType:    SHA256,
}

var YaraRule = Kind{
	Kind:        "yara-rule",
	Description: "Yara rule",
	DataType:    STR,
}

var SuricataRule = Kind{
	Kind:        "suricata-rule",
	Description: "Suricata rule",
	DataType:    STR,
}

var OSSECRule = Kind{
	Kind:        "ossec-rule",
	Description: "OSSEC rule",
	DataType:    STR,
}

var ElasticRule = Kind{
	Kind:        "elastic-rule",
	Description: "Elasticsearch rule",
	DataType:    STR,
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
