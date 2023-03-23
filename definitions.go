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

type Definition struct {
	Type         string      `json:"type" example:"object"`
	Description  string      `json:"description" example:"Important description about the type"`
	DataType     string      `json:"dataType" example:"String"`
	Example      interface{} `json:"example,omitempty" example:"6ee84de3-3d2d-4a70-a918-d0e590d350e0"`
	Attributes   []Definition      `json:"attributes,omitempty"`
	Associations []Definition      `json:"associations,omitempty"`
}

var File = Definition{
	Type:         "file",
	Description:  "Object identifying a file, the value can be a UUID or a SHA3-256 or MD5 checksum",
	DataType:     ISTR,
	Associations: []Definition{Filename, FileData, HashSHA1, HashMD5, HashSHA256, HashSHA3256, FilenamePattern},
}

var FileData = Definition{
	Type:        "file-data",
	Description: "File or attachment URL",
	DataType:    URL,
	Attributes:  []Definition{SizeInBytes, HashMD5, HashSHA3256, HashSHA1, HashSHA256},
}

var VirusTotalReport = Definition{
	Type:        "virustotal-report",
	Description: "VirusTotal report",
	DataType:    URL,
	Attributes:  []Definition{Datetime},
}

var Adversary = Definition{
	Type:        "adversary",
	Description: "Object identifying a threat actor",
	DataType:    ISTR,
}

var ASO = Definition{
	Type:        "aso",
	Description: "Autonomous System Organization",
	DataType:    ISTR,
}

var ASN = Definition{
	Type:        "asn",
	Description: "Autonomous System Organization Number",
	DataType:    INTEGER,
}

var Malware = Definition{
	Type:        "malware",
	Description: "Malware",
	DataType:    ISTR,
	Attributes: []Definition{
		MalwareFamily,
		MalwareType,
	},
}

var Object = Definition{
	Type:        "object",
	Description: "Generic entity composed of other entities, the value can be a UUID or a SHA3-256 or MD5 checksum",
	DataType:    ISTR,
	Attributes: []Definition{
		Descriptor,
	},
}

var Descriptor = Definition{
	Type:        "descriptor",
	DataType:    ISTR,
	Description: "The object descriptor",
}

var ABARTN = Definition{
	Type:        "aba-rtn",
	Description: "ABA routing transit number",
	DataType:    INTEGER,
}

var Latitude = Definition{
	Type:        "latitude",
	Description: "GPS latitude",
	Example:     40.741895,
	DataType:    FLOAT,
}

var Longitude = Definition{
	Type:        "longitude",
	Description: "GPS longitude",
	Example:     40.741895,
	DataType:    FLOAT,
}

var Country = Definition{
	Type:        "country",
	Description: "Country name",
	Example:     "Estonia",
	DataType:    COUNTRY,
}

var Cookie = Definition{
	Type:        "cookie",
	Description: "HTTP cookie as often stored on the user web client. This can include authentication cookie or session cookie",
	DataType:    STR,
	Attributes:  []Definition{Value},
}

var Text = Definition{
	Type:        "text",
	Description: "Any case insensitive text value",
	DataType:    ISTR,
}

var Value = Definition{
	Type:        "value",
	Description: "Any case sensitive text value",
	DataType:    STR,
}

var Password = Definition{
	Type:        "password",
	Description: "Password",
	DataType:    STR,
}

var Airport = Definition{
	Type:        "airport-name",
	Description: "The airport name",
	DataType:    ISTR,
	Attributes:  []Definition{Country, City},
}

var ProfilePhoto = Definition{
	Type:        "profile-photo",
	Description: "Profile photo URL",
	DataType:    URL,
}

var AuthentiHash = Definition{
	Type:        "authentihash",
	Description: "Authenticode executable signature hash",
	DataType:    HEXADECIMAL,
}

var BankAccountNr = Definition{
	Type:        "bank-account-nr",
	Description: "Bank account number without any routing number",
	DataType:    INTEGER,
	Attributes:  []Definition{BIC, BIN},
}

var BIC = Definition{
	Type:        "bic",
	Description: "Bank Identifier Code Number also known as SWIFT-BIC, SWIFT code or ISO 9362 code",
	DataType:    ISTR,
}

var BIN = Definition{
	Type:        "bin",
	Description: "Bank Identification Number",
	DataType:    INTEGER,
}

var BTC = Definition{
	Type:        "btc",
	Description: "Bitcoin Address",
	DataType:    STR,
}

var CCNumber = Definition{
	Type:        "cc-number",
	Description: "Credit-Card Number",
	DataType:    INTEGER,
	Attributes:  []Definition{Issuer},
}

var Issuer = Definition{
	Type:        "issuer",
	Description: "Issuer name",
	DataType:    ISTR,
}

var CDHash = Definition{
	Type:        "cdhash",
	Description: "An Apple Code Directory Hash, identifying a code-signed Mach-O executable file",
	DataType:    HEXADECIMAL,
}

var CertificateFingerprint = Definition{
	Type:        "certificate-fingerprint",
	Description: "The fingerprint of a SSL/TLS certificate",
	DataType:    HEXADECIMAL,
}

var ChromeExtension = Definition{
	Type:        "chrome-extension-id",
	Description: "Chrome extension ID",
	DataType:    STR,
}

var Subnet = Definition{
	Type:        "cidr",
	Description: "A public network segment",
	DataType:    CIDR,
	Example: "140.40.24.0/24",
	Attributes:  []Definition{Country, City, Latitude, Longitude, ASN, ASO},
}

var CPE = Definition{
	Type:        "cpe",
	Description: "Common Platform Enumeration. Structured naming scheme for information technology systems, software, and packages",
	DataType:    ISTR,
}

var CVE = Definition{
	Type:        "cve",
	Description: "",
	DataType:    ISTR,
}

var Dash = Definition{
	Type:        "dash",
	Description: "Dash address",
	DataType:    STR,
}

var DKIM = Definition{
	Type:        "dkim",
	Description: "DKIM public key",
	DataType:    STR,
}

var DKIMSignature = Definition{
	Type:        "dkim-signature",
	Description: "DKIM signature",
	DataType:    STR,
}

var Domain = Definition{
	Type:        "domain",
	Description: "Internet domain",
	Example:     "example.com",
	DataType:    DOMAIN,
	Attributes:  []Definition{WhoIsRegistrant, WhoIsRegistrar},
}

var Email = Definition{
	Type:        "email",
	Description: "Email Message ID",
	DataType:    STR,
	Example:     "950124.162336@example.com",
	Attributes:  []Definition{EmailBody, EmailDisplayName, EmailHeader, EmailAddress, EmailSubject},
}

var City = Definition{
	Type:        "city",
	Description: "City name",
	DataType:    CITY,
}

var IssuingCountry = Definition{
	Type:        "issuing-country",
	Description: "Issuing country name",
	DataType:    COUNTRY,
}

var EmailAddress = Definition{
	Type:        "email-address",
	Description: "Sender email address",
	DataType:    EMAIL,
}

var EmailBody = Definition{
	Type:        "email-body",
	Description: "Email body",
	DataType:    ISTR,
}

var EmailDisplayName = Definition{
	Type:        "email-display-name",
	Description: "Sender display name",
	DataType:    ISTR,
}

var EmailHeader = Definition{
	Type:        "email-header",
	Description: "Email header (all headers)",
	DataType:    STR,
}

var EmailMimeBoundary = Definition{
	Type:        "email-mime-boundary",
	Description: "MIME boundaries are strings of 7-bit US-ASCII text that define the boundaries between message parts in a MIME message. MIME boundaries are declared in a Content-Type message header for any message that encapsulates more than one message part and in part headers for those parts that encapsulate nested parts.",
	DataType:    STR,
}

var EmailSubject = Definition{
	Type:        "email-subject",
	Description: "The subject of the email",
	DataType:    ISTR,
}

var EmailThreadIndex = Definition{
	Type:        "email-thread-index",
	Description: "The email thread index",
	DataType:    BASE64,
}

var EmailXMailer = Definition{
	Type:        "email-x-mailer",
	Description: "Email x-mailer header",
	DataType:    ISTR,
}

var EPPN = Definition{
	Type:        "eppn",
	Description: "The NetId of the person for the purposes of inter-institutional authentication. Should be stored in the form of user@univ.edu, where univ.edu is the name of the local security domain",
	DataType:    EMAIL,
}

var FacebookID = Definition{
	Type:        "facebook-id",
	Description: "Facebook profile",
	DataType:    URL,
}

var FFN = Definition{
	Type:        "ffn",
	Description: "The frequent flyer number of a passanger",
	DataType:    STR,
}

var Filename = Definition{
	Type:        "filename",
	Description: "A filename or email attachment name",
	DataType:    ISTR,
}

var SizeInBytes = Definition{
	Type:        "size-in-bytes",
	Description: "The size in bytes of an element",
	DataType:    FLOAT,
}

var FilenamePattern = Definition{
	Type:        "filename-pattern",
	Description: "A pattern in the name of a file",
	DataType:    STR,
}

var Flight = Definition{
	Type:        "flight",
	Description: "A flight number",
	DataType:    STR,
}

var GENE = Definition{
	Type:        "gene",
	Description: "Go Evtx sigNature Engine",
	DataType:    STR,
}

var GitHubOrganization = Definition{
	Type:        "github-organization",
	Description: "Github organization",
	DataType:    URL,
}

var GitHubRepository = Definition{
	Type:        "github-repository",
	Description: "Github repository",
	DataType:    URL,
}

var GitHubUser = Definition{
	Type:        "github-user",
	Description: "Github user",
	DataType:    URL,
}

var Link = Definition{
	Type:        "link",
	Description: "External link for reference",
	DataType:    URL,
}

var Datetime = Definition{
	Type:        "datetime",
	Description: "Time with nanoseconds in the format 2006-01-02T15:04:05.999999999Z07:00",
	DataType:    DATETIME,
}

var Date = Definition{
	Type:        "date",
	Description: "Date in format 2006-01-02",
	DataType:    DATE,
}

var MalwareSample = Definition{
	Type:        "malware-sample",
	Description: "Malware Sample URL",
	DataType:    URL,
	Attributes:  []Definition{Malware, File},
}

var Group = Definition{
	Type:        "group",
	Description: "Adversaries group",
	DataType:    ISTR,
}

var HaSSHMD5 = Definition{
	Type:        "hassh-md5",
	Description: "Network fingerprinting standard which can be used to identify specific Client SSH implementations. The fingerprints can be easily stored, searched and shared in the form of an MD5 fingerprint",
	DataType:    MD5,
}

var HaSSHServerMD5 = Definition{
	Type:        "hasshserver-md5",
	Description: "Network fingerprinting standard which can be used to identify specific Server SSH implementations. The fingerprints can be easily stored, searched and shared in the form of an MD5 fingerprint",
	DataType:    MD5,
}

var Hex = Definition{
	Type:        "hex",
	Description: "A value in hexadecimal",
	DataType:    HEXADECIMAL,
}

var Base64 = Definition{
	Type:        "base64",
	Description: "A value in BASE64 format",
	DataType:    BASE64,
}

var Hostname = Definition{
	Type:        "hostname",
	Description: "A full host/dnsname of an attacker",
	DataType:    HOSTNAME,
}

var IBAN = Definition{
	Type:        "iban",
	Description: "International Bank Account Number",
	DataType:    ISTR,
}

var IDNumber = Definition{
	Type:        "id-number",
	Description: "It can be an ID card, residence permit, etc.",
	DataType:    STR,
	Attributes:  []Definition{Issuer, IssuingCountry, Date},
}

var IPAddr = Definition{
	Type:        "ip",
	Description: "IP Address",
	DataType:    IP,
	Example:     "8.8.8.8",
	Attributes:  []Definition{Subnet},
}

var JA3Fingerprint = Definition{
	Type:        "ja3-fingerprint-md5",
	Description: "JA3 is a method for creating SSL/TLS client fingerprints that should be easy to produce on any platform and can be easily shared for threat intelligence",
	DataType:    MD5,
}

var JabberID = Definition{
	Type:        "jabber-id",
	Description: "Jabber ID",
	DataType:    EMAIL,
}

var JARMFingerprint = Definition{
	Type:        "jarm-fingerprint",
	Description: "JARM is a method for creating SSL/TLS server fingerprints",
	DataType:    HEXADECIMAL,
}

var MACAddr = Definition{
	Type:        "mac-address",
	Description: "Network interface hardware address",
	DataType:    MAC,
}

var MalwareFamily = Definition{
	Type:        "malware-family",
	Description: "Malware family",
	DataType:    ISTR,
}

var MalwareType = Definition{
	Type:        "malware-type",
	Description: "Malware type",
	DataType:    ISTR,
}

var HashMD5 = Definition{
	Type:        "md5",
	Description: "Hash MD5",
	DataType:    MD5,
}

var MimeType = Definition{
	Type:        "mime-type",
	Description: "A media type (also MIME type and content type) is a two-part identifier",
	DataType:    MIME,
}

var MobileAppID = Definition{
	Type:        "mobile-app-id",
	Description: "The ID of a mobile application",
	DataType:    STR,
}

var Passport = Definition{
	Type:        "passport",
	Description: "Passport number",
	DataType:    STR,
	Attributes:  []Definition{IssuingCountry, Issuer, Date},
}

var Path = Definition{
	Type:        "path",
	Description: "Path to a file, folder or process, also a HTTP request path",
	DataType:    STR,
}

var PatternInFile = Definition{
	Type:        "pattern-in-file",
	Description: "Pattern inside a file",
	DataType:    STR,
}

var PatternInMemory = Definition{
	Type:        "pattern-in-memory",
	Description: "Pattern in memory",
	DataType:    STR,
}

var PatternInTraffic = Definition{
	Type:        "pattern-in-traffic",
	Description: "Pattern in traffic",
	DataType:    STR,
}

var PGPPrivateKey = Definition{
	Type:        "pgp-private-key",
	Description: "PGP private key",
	DataType:    STR,
}

var PGPPublicKey = Definition{
	Type:        "pgp-public-key",
	Description: "PGP public key",
	DataType:    STR,
}

var Phone = Definition{
	Type:        "phone",
	Description: "Phone number",
	DataType:    PHONE,
}

var PNR = Definition{
	Type:        "pnr",
	Description: "The Passenger Name Record Locator is a key under which the reservation for a trip is stored in the system. The PNR contains, among other data, the name, flight segments and address of the passenger. It is defined by a combination of five or six letters and numbers",
	DataType:    STR,
}

var Process = Definition{
	Type:        "process",
	Description: "A running process",
	DataType:    ISTR,
	Attributes:  []Definition{ProcessState},
}

var ProcessState = Definition{
	Type:        "process-state",
	Description: "State of a process",
	DataType:    ISTR,
}

var PRTN = Definition{
	Type:        "prtn",
	Description: "Premium-rate telephone number",
	DataType:    ISTR,
}

var Redress = Definition{
	Type:        "redress-number",
	Description: "The Redress Control Number is the record identifier for people who apply for redress through the DHS Travel Redress Inquiry Program (DHS TRIP). DHS TRIP is for travelers who have been repeatedly identified for additional screening and who want to file an inquiry to have erroneous information corrected in DHS systems",
	DataType:    STR,
}

var RegKey = Definition{
	Type:        "regkey",
	Description: "Registry key",
	DataType:    ISTR,
}

var HashSHA1 = Definition{
	Type:        "sha1",
	Description: "Hash SHA1",
	DataType:    SHA1,
}

var HashSHA224 = Definition{
	Type:        "sha224",
	Description: "Hash SHA224",
	DataType:    SHA224,
}

var HashSHA256 = Definition{
	Type:        "sha256",
	Description: "Hash SHA256",
	DataType:    SHA256,
}

var HashSHA384 = Definition{
	Type:        "sha384",
	Description: "Hash SHA384",
	DataType:    SHA384,
}

var HashSHA512 = Definition{
	Type:        "sha512",
	Description: "Hash SHA512",
	DataType:    SHA512,
}

var HashSHA3224 = Definition{
	Type:        "sha3-224",
	Description: "Hash SHA3-224",
	DataType:    SHA3_224,
}

var HashSHA3256 = Definition{
	Type:        "sha3-256",
	Description: "Hash SHA3-256",
	DataType:    SHA3_256,
}

var HashSHA3384 = Definition{
	Type:        "sha3-384",
	Description: "Hash SHA3-384",
	DataType:    SHA3_384,
}

var HashSHA3512 = Definition{
	Type:        "sha3-512",
	Description: "Hash SHA3-512",
	DataType:    SHA3_512,
}

var HashSHA512224 = Definition{
	Type:        "sha512-224",
	Description: "Hash SHA512-224",
	DataType:    SHA512_224,
}

var HashSHA512256 = Definition{
	Type:        "sha512-256",
	Description: "Hash SHA512-256",
	DataType:    SHA512_256,
}

var SSHFingerprint = Definition{
	Type:        "ssh-fingerprint",
	Description: "A fingerprint of SSH key material",
	DataType:    STR,
}

var SSR = Definition{
	Type:        "ssr",
	Description: "A Special Service Request is a function to an airline to provide a particular facility for A Passenger or passengers",
	DataType:    STR,
}

var Category = Definition{
	Type:        "category",
	Description: "A category",
	DataType:    ISTR,
}

var Threat = Definition{
	Type:        "threat",
	Description: "A cybersecurity threat",
	DataType:    ISTR,
}

var TikTokID = Definition{
	Type:        "tiktok-id",
	Description: "TikTok user ID",
	DataType:    URL,
}

var TwitterID = Definition{
	Type:        "twitter-id",
	Description: "A Twitter user ID",
	DataType:    URL,
}

var URI = Definition{
	Type:        "url",
	Description: "URL",
	DataType:    URL,
}

var Username = Definition{
	Type:        "username",
	Description: "Username",
	DataType:    ISTR,
}

var Visa = Definition{
	Type:        "visa",
	Description: "Visa number",
	DataType:    STR,
}

var WhoIsRegistrant = Definition{
	Type:        "whois-registrant",
	Description: "Who is registrant",
	DataType:    ISTR,
}

var WhoIsRegistrar = Definition{
	Type:        "whois-registrar",
	Description: "whois-registrar",
	DataType:    ISTR,
}

var WindowsScheduledTask = Definition{
	Type:        "windows-scheduled-task",
	Description: "A Windows scheduled task",
	DataType:    ISTR,
}

var WindowsServiceDisplayName = Definition{
	Type:        "windows-service-displayname",
	Description: "A windows service’s displayname, not to be confused with the windows-service-name. This is the name that applications will generally display as the service’s name in applications",
	DataType:    ISTR,
}

var WindowsServiceName = Definition{
	Type:        "windows-service-name",
	Description: "A windows service name. This is the name used internally by windows. Not to be confused with the windows-service-displayname",
	DataType:    ISTR,
}

var XMR = Definition{
	Type:        "xmr",
	Description: "Monero address",
	DataType:    STR,
}

var X509MD5 = Definition{
	Type:        "x509-fingerprint-md5",
	Description: "X509 fingerprint in MD5",
	DataType:    MD5,
}

var X509SHA1 = Definition{
	Type:        "x509-fingerprint-sha1",
	Description: "X509 fingerprint in SHA1",
	DataType:    SHA1,
}

var X509SHA256 = Definition{
	Type:        "x509-fingerprint-sha256",
	Description: "X509 fingerprint in SHA256",
	DataType:    SHA256,
}

var YaraRule = Definition{
	Type:        "yara-rule",
	Description: "Yara rule",
	DataType:    STR,
}

var SuricataRule = Definition{
	Type:        "suricata-rule",
	Description: "Suricata rule",
	DataType:    STR,
}

var OSSECRule = Definition{
	Type:        "ossec-rule",
	Description: "OSSEC rule",
	DataType:    STR,
}

var ElasticRule = Definition{
	Type:        "elastic-rule",
	Description: "Elasticsearch rule",
	DataType:    STR,
}

var Definitions = []Definition{
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
