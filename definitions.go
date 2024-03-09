package validations

const (
	STR         = "Case-sensitive string"
	IP          = "IP"
	EMAIL       = "Email"
	FQDN        = "FQDN"
	INTEGER     = "Integer"
	CIDR        = "CIDR"
	CITY        = "City"
	COUNTRY     = "Country"
	FLOAT       = "Float"
	URL         = "URL"
	MD5         = "MD5"
	HEXADECIMAL = "Hexadecimal"
	BASE64      = "BASE64"
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
	PATH        = "Path"
	OBJECT      = "UUID|MD5|SHA3-256"
	ADVERSARY   = "Adversary"
	REGEX       = "Regex"
	PORT		= "Port"
)

type Definition struct {
	Type         string       `json:"type" example:"object"`
	Description  string       `json:"description" example:"Important description about the type"`
	DataType     string       `json:"dataType" example:"String"`
	Example      *Entity      `json:"example,omitempty"`
	Attributes   []Definition `json:"attributes,omitempty"`
	Associations []Definition `json:"associations,omitempty"`
	Tags         []string     `json:"tags,omitempty"`
	Correlate    []string     `json:"correlate,omitempty"`
	Label        string       `json:"label,omitempty"`
}

var file = Definition{
	Type:         "file",
	Description:  "Object identifying a file, the value can be a UUID or a SHA3-256 or MD5 checksum",
	DataType:     OBJECT,
	Attributes:   []Definition{fileData, hashSHA1, hashMD5, hashSHA256, hashSHA3256},
	Associations: []Definition{filename, filenamePattern},
	Tags:         []string{"malware", "common-file", "system-file"},
	Correlate:    []string{"md5", "sha1", "sha256", "sha3-256", "file-data"},
	Example:      &eFile,
	Label:        "File",
}

var payload = Definition{
	Type:        "payload",
	Description: "SHA3-256 of a message sent in a network packet",
	DataType:    SHA3_256,
	Attributes:  []Definition{hashSHA1, hashMD5, hashSHA256, hashSHA3256},
	Label:       "Payload",
}

var fileData = Definition{
	Type:        "file-data",
	Description: "File or attachment URL",
	DataType:    URL,
	Attributes:  []Definition{},
	Label:       "Download",
}

var adversary = Definition{
	Type:        "adversary",
	Description: "Object identifying a threat actor",
	DataType:    ADVERSARY,
	Label:       "Adversary",
}

var aso = Definition{
	Type:        "aso",
	Description: "Autonomous System Organization",
	DataType:    ISTR,
	Label:       "ASO",
}

var asn = Definition{
	Type:        "asn",
	Description: "Autonomous System Organization Number",
	DataType:    INTEGER,
	Label:       "ASN",
}

var malware = Definition{
	Type:        "malware",
	Description: "Malware",
	DataType:    ISTR,
	Attributes: []Definition{
		malwareFamily,
		malwareType,
	},
	Correlate: []string{"malware-family", "malware-type"},
	Example:   &eMalware,
	Label:     "Malware Name",
}

var abaRtn = Definition{
	Type:        "aba-rtn",
	Description: "ABA routing transit number",
	DataType:    INTEGER,
	Label:       "ABA RTN",
}

var latitude = Definition{
	Type:        "latitude",
	Description: "GPS latitude",
	DataType:    FLOAT,
	Label:       "Latitude",
}

var longitude = Definition{
	Type:        "longitude",
	Description: "GPS longitude",
	DataType:    FLOAT,
	Label:       "Longitude",
}

var country = Definition{
	Type:        "country",
	Description: "Country name",
	DataType:    COUNTRY,
	Label:       "Country",
}

var city = Definition{
	Type:        "city",
	Description: "City name",
	DataType:    CITY,
	Label:       "City",
}

var cookie = Definition{
	Type:         "cookie",
	Description:  "HTTP cookie as often stored on the user web client. This can include authentication cookie or session cookie",
	DataType:     STR,
	Associations: []Definition{value},
	Label:        "Cookie",
}

var text = Definition{
	Type:        "text",
	Description: "Any case insensitive text value",
	DataType:    ISTR,
	Label:       "Text",
}

var value = Definition{
	Type:        "value",
	Description: "Any case sensitive text value",
	DataType:    STR,
	Label:       "Text",
}

var password = Definition{
	Type:        "password",
	Description: "Password",
	DataType:    STR,
	Label:       "Password",
}

var airport = Definition{
	Type:        "airport-name",
	Description: "The airport name",
	DataType:    ISTR,
	Attributes:  []Definition{country, city},
	Label:       "Airport",
}

var profilePhoto = Definition{
	Type:        "profile-photo",
	Description: "Profile photo URL",
	DataType:    URL,
	Label:       "Profile Photo",
}

var authentiHash = Definition{
	Type:        "authentihash",
	Description: "Authenticode executable signature hash",
	DataType:    HEXADECIMAL,
	Label:       "Authenticode Hash",
}

var bankAccountNr = Definition{
	Type:        "bank-account-nr",
	Description: "Bank account number without any routing number",
	DataType:    INTEGER,
	Attributes:  []Definition{bic, bin},
	Label:       "Bank Account",
}

var bic = Definition{
	Type:        "bic",
	Description: "Bank Identifier Code also known as SWIFT-BIC, SWIFT code or ISO 9362 code",
	DataType:    ISTR,
	Label:       "BIC",
}

var bin = Definition{
	Type:        "bin",
	Description: "Bank Identification Number",
	DataType:    INTEGER,
	Label:       "BIN",
}

var btc = Definition{
	Type:        "btc",
	Description: "Bitcoin Address",
	DataType:    STR,
	Label:       "Bitcoin Address",
}

var ccNumber = Definition{
	Type:        "cc-number",
	Description: "Credit Card Number",
	DataType:    INTEGER,
	Attributes:  []Definition{issuer},
	Label:       "Credit Card",
}

var issuer = Definition{
	Type:        "issuer",
	Description: "Issuer name",
	DataType:    ISTR,
	Label:       "Issuer",
}

var issuingCountry = Definition{
	Type:        "issuing-country",
	Description: "Issuing country name",
	DataType:    COUNTRY,
	Label:       "Issuing Country",
}

var cdHash = Definition{
	Type:        "cdhash",
	Description: "An Apple Code Directory Hash, identifying a code-signed Mach-O executable file",
	DataType:    HEXADECIMAL,
	Label:       "Code Directory Hash",
}

var certificateFingerprint = Definition{
	Type:        "certificate-fingerprint",
	Description: "The fingerprint of a SSL/TLS certificate",
	DataType:    HEXADECIMAL,
	Label:       "Certificate Fingerprint",
}

var chromeExtension = Definition{
	Type:        "chrome-extension-id",
	Description: "Chrome extension ID",
	DataType:    STR,
	Label:       "Chrome Extension",
}

var subnet = Definition{
	Type:        "cidr",
	Description: "A public network segment",
	DataType:    CIDR,
	Attributes:  []Definition{country, city, latitude, longitude, asn, aso},
	Label:       "Public Subnet",
}

var cpe = Definition{
	Type:        "cpe",
	Description: "Common Platform Enumeration. Structured naming scheme for information technology systems, software, and packages",
	DataType:    ISTR,
	Label:       "Platform Enumeration",
}

var cve = Definition{
	Type:        "cve",
	Description: "Common Vulnerability Enumerator",
	DataType:    ISTR,
	Label:       "Vulnerability Enumeration",
}

var dash = Definition{
	Type:        "dash",
	Description: "Dash address",
	DataType:    STR,
	Label:       "Dash",
}

var dkim = Definition{
	Type:        "dkim",
	Description: "DKIM public key",
	DataType:    STR,
	Label:       "DKIM Public Key",
}

var dkimSignature = Definition{
	Type:        "dkim-signature",
	Description: "DKIM signature",
	DataType:    STR,
	Label:       "DKIM Signature",
}

var domain = Definition{
	Type:        "domain",
	Description: "Internet domain",
	DataType:    FQDN,
	Attributes:  []Definition{whoIsRegistrant, whoIsRegistrar},
	Label:       "Domain",
}

var email = Definition{
	Type:         "email",
	Description:  "Email Message ID",
	DataType:     STR,
	Attributes:   []Definition{emailBody, emailDisplayName, emailAddress, emailSubject, emailThreadIndex, emailMimeBoundary, emailXMailer},
	Associations: []Definition{file, emailHeader},
	Label:        "Message ID",
}

var emailAddress = Definition{
	Type:        "email-address",
	Description: "Sender email address",
	DataType:    EMAIL,
	Label:       "Email",
}

var emailBody = Definition{
	Type:        "email-body",
	Description: "Email body",
	DataType:    ISTR,
	Label:       "Email Body",
}

var emailDisplayName = Definition{
	Type:        "email-display-name",
	Description: "Sender display name",
	DataType:    ISTR,
	Label:       "Sender Display Name",
}

var emailHeader = Definition{
	Type:        "email-header",
	Description: "Email header",
	DataType:    STR,
	Label:       "Email Header",
}

var emailMimeBoundary = Definition{
	Type:        "email-mime-boundary",
	Description: "MIME boundaries are strings of 7-bit US-ASCII text that define the boundaries between message parts in a MIME message. MIME boundaries are declared in a Content-Type message header for any message that encapsulates more than one message part and in part headers for those parts that encapsulate nested parts.",
	DataType:    STR,
	Label:       "Email Mime Boundary",
}

var emailSubject = Definition{
	Type:        "email-subject",
	Description: "The subject of the email",
	DataType:    ISTR,
	Label:       "Email Subject",
}

var emailThreadIndex = Definition{
	Type:        "email-thread-index",
	Description: "The email thread index",
	DataType:    BASE64,
	Label:       "Email Thread Index",
}

var emailXMailer = Definition{
	Type:        "email-x-mailer",
	Description: "Email x-mailer header",
	DataType:    ISTR,
	Label:       "Email X-Mailer",
}

var eppn = Definition{
	Type:        "eppn",
	Description: "The NetId of the person for the purposes of inter-institutional authentication. Should be stored in the form of user@univ.edu, where univ.edu is the name of the local security domain",
	DataType:    EMAIL,
	Label:       "EPPN",
}

var facebookProfile = Definition{
	Type:        "facebook-profile",
	Description: "Facebook profile",
	DataType:    URL,
	Label:       "Facebook Profile",
}

var ffn = Definition{
	Type:        "ffn",
	Description: "The frequent flyer number of a passanger",
	DataType:    STR,
	Label:       "Frequent Flyer Number",
}

var filename = Definition{
	Type:        "filename",
	Description: "A filename or email attachment name",
	DataType:    ISTR,
	Label:       "File Name",
}

var sizeInBytes = Definition{
	Type:        "size-in-bytes",
	Description: "The size in bytes of an element",
	DataType:    FLOAT,
	Label:       "Size (Bytes)",
}

var filenamePattern = Definition{
	Type:        "filename-pattern",
	Description: "A pattern in the name of a file",
	DataType:    REGEX,
	Label:       "Filename Pattern",
}

var flight = Definition{
	Type:        "flight",
	Description: "A flight number",
	DataType:    STR,
	Label:       "Flight Number",
}

var gitHubOrganization = Definition{
	Type:        "github-organization",
	Description: "Github organization",
	DataType:    URL,
	Label:       "GitHub Organization",
}

var gitHubRepository = Definition{
	Type:        "github-repository",
	Description: "Github repository",
	DataType:    URL,
	Label:       "GitHub Repo",
}

var gitHubUser = Definition{
	Type:        "github-user",
	Description: "Github user",
	DataType:    URL,
	Label:       "GitHub Profile",
}

var link = Definition{
	Type:        "link",
	Description: "External link for reference",
	DataType:    URL,
	Label:       "Reference",
}

var datetime = Definition{
	Type:        "datetime",
	Description: "Time with nanoseconds in the format 2006-01-02T15:04:05.999999999Z07:00",
	DataType:    DATETIME,
	Label:       "Date & Time",
}

var lastAnalysis = Definition{
	Type:        "last-analysis",
	Description: "Time of last analysis. Format 2006-01-02T15:04:05.999999999Z",
	DataType:    DATETIME,
	Label:       "Last Analysis",
}

var date = Definition{
	Type:        "date",
	Description: "Date in format 2006-01-02",
	DataType:    DATE,
	Label:       "Date",
}

var dateOfIssue = Definition{
	Type:        "date-of-issue",
	Description: "Date in format 2006-01-02",
	DataType:    DATE,
	Label:       "Date of Issue",
}

var expirationDate = Definition{
	Type:        "expiration-date",
	Description: "Date in format 2006-01-02",
	DataType:    DATE,
	Label:       "Due Date",
}

var malwareSample = Definition{
	Type:        "malware-sample",
	Description: "Malware Sample URL",
	DataType:    URL,
	Label:       "Malware Sample",
}

var group = Definition{
	Type:        "group",
	Description: "Group of adversaries like APTnn or Anonymous",
	DataType:    ADVERSARY,
	Label:       "Group",
}

var haSSHMD5 = Definition{
	Type:        "hassh-md5",
	Description: "Network fingerprinting standard which can be used to identify specific SSH client implementations. The fingerprints can be easily stored, searched and shared in the form of an MD5 fingerprint",
	DataType:    MD5,
	Label:       "SSH Client Fingerprint",
}

var haSSHServerMD5 = Definition{
	Type:        "hasshserver-md5",
	Description: "Network fingerprinting standard which can be used to identify specific Server SSH implementations. The fingerprints can be easily stored, searched and shared in the form of an MD5 fingerprint",
	DataType:    MD5,
	Label:       "SSH Server Fingerprint",
}

var hexa = Definition{
	Type:        "hex",
	Description: "A value in hexadecimal",
	DataType:    HEXADECIMAL,
	Label:       "Hexadecimal",
}

var base64d = Definition{
	Type:        "base64",
	Description: "A value in BASE64 format",
	DataType:    BASE64,
	Label:       "Base64",
}

var hostname = Definition{
	Type:        "hostname",
	Description: "A full host/dnsname of an attacker",
	DataType:    FQDN,
	Label:       "Host",
}

var iban = Definition{
	Type:        "iban",
	Description: "International Bank Account Number",
	DataType:    ISTR,
	Label:       "IBAN",
}

var idNumber = Definition{
	Type:        "id-number",
	Description: "It can be an ID card, residence permit, etc.",
	DataType:    STR,
	Attributes:  []Definition{issuer, dateOfIssue, expirationDate},
	Label:       "Identity Number",
}

var ipAddr = Definition{
	Type:        "ip",
	Description: "IP Address",
	DataType:    IP,
	Attributes:  []Definition{subnet},
	Label:       "IP",
}

var ja3Fingerprint = Definition{
	Type:        "ja3-fingerprint-md5",
	Description: "JA3 is a method for creating SSL/TLS client fingerprints that should be easy to produce on any platform and can be easily shared for threat intelligence",
	DataType:    MD5,
	Label:       "JA3 Fingerprint",
}

var jabberID = Definition{
	Type:        "jabber-id",
	Description: "Jabber ID",
	DataType:    EMAIL,
	Label:       "Jabber ID",
}

var jarmFingerprint = Definition{
	Type:        "jarm-fingerprint",
	Description: "JARM is a method for creating SSL/TLS server fingerprints",
	DataType:    HEXADECIMAL,
	Label:       "JARM Fingerprint",
}

var macAddr = Definition{
	Type:        "mac-address",
	Description: "Network interface hardware address",
	DataType:    MAC,
	Label:       "Hardware Address",
}

var malwareFamily = Definition{
	Type:        "malware-family",
	Description: "Malware family",
	DataType:    ISTR,
	Label:       "Malware Family",
}

var malwareType = Definition{
	Type:        "malware-type",
	Description: "Malware type",
	DataType:    ISTR,
	Label:       "Malware Type",
}

var hashMD5 = Definition{
	Type:        "md5",
	Description: "Hash MD5",
	DataType:    MD5,
	Label:       "MD5",
}

var mimeType = Definition{
	Type:        "mime-type",
	Description: "A media type (also MIME type and content type) is a two-part identifier",
	DataType:    MIME,
	Label:       "Media Type",
}

var mobileAppID = Definition{
	Type:        "mobile-app-id",
	Description: "The ID of a mobile application",
	DataType:    STR,
	Label:       "Mobile App ID",
}

var passport = Definition{
	Type:        "passport",
	Description: "Passport number",
	DataType:    STR,
	Attributes:  []Definition{issuingCountry, issuer, dateOfIssue, expirationDate},
	Label:       "Passport Number",
}

var pathD = Definition{
	Type:        "path",
	Description: "Path to a file, folder or process, also a HTTP request path",
	DataType:    PATH,
	Label:       "Path",
}

var patternInFile = Definition{
	Type:        "pattern-in-file",
	Description: "Pattern inside a file",
	DataType:    REGEX,
	Label:       "Pattern in File",
}

var patternInMemory = Definition{
	Type:        "pattern-in-memory",
	Description: "Pattern in memory",
	DataType:    REGEX,
	Label:       "Pattern in Memory",
}

var patternInTraffic = Definition{
	Type:        "pattern-in-traffic",
	Description: "Pattern in traffic",
	DataType:    REGEX,
	Label:       "Pattern in Traffic",
}

var pgpPrivateKey = Definition{
	Type:        "pgp-private-key",
	Description: "PGP private key",
	DataType:    STR,
	Label:       "PGP Private Key",
}

var pgpPublicKey = Definition{
	Type:        "pgp-public-key",
	Description: "PGP public key",
	DataType:    STR,
	Label:       "PGP Public Key",
}

var phone = Definition{
	Type:        "phone",
	Description: "Phone number",
	DataType:    PHONE,
	Label:       "Phone Number",
}

var pnr = Definition{
	Type:        "pnr",
	Description: "The Passenger Name Record Locator is a key under which the reservation for a trip is stored in the system. The PNR contains, among other data, the name, flight segments and address of the passenger. It is defined by a combination of five or six letters and numbers",
	DataType:    STR,
	Label:       "Reservation Number",
}

var process = Definition{
	Type:        "process",
	Description: "A running process",
	DataType:    ISTR,
	Attributes:  []Definition{processState},
	Label:       "Process",
}

var processState = Definition{
	Type:        "process-state",
	Description: "State of a process",
	DataType:    ISTR,
	Label:       "Process State",
}

var pRtn = Definition{
	Type:        "prtn",
	Description: "Premium-rate telephone number",
	DataType:    ISTR,
	Label:       "PRTN",
}

var redress = Definition{
	Type:        "redress-number",
	Description: "The Redress Control Number is the record identifier for people who apply for redress through the DHS Travel Redress Inquiry Program (DHS TRIP). DHS TRIP is for travelers who have been repeatedly identified for additional screening and who want to file an inquiry to have erroneous information corrected in DHS systems",
	DataType:    STR,
	Label:       "Redress Control Number",
}

var regKey = Definition{
	Type:        "regkey",
	Description: "Registry key",
	DataType:    ISTR,
	Label:       "Registry Key",
}

var hashSHA1 = Definition{
	Type:        "sha1",
	Description: "Hash SHA1",
	DataType:    SHA1,
	Label:       "SHA-1",
}

var hashSHA224 = Definition{
	Type:        "sha224",
	Description: "Hash SHA-224",
	DataType:    SHA224,
	Label:       "SHA-224",
}

var hashSHA256 = Definition{
	Type:        "sha256",
	Description: "Hash SHA-256",
	DataType:    SHA256,
	Label:       "SHA-256",
}

var hashSHA384 = Definition{
	Type:        "sha384",
	Description: "Hash SHA-384",
	DataType:    SHA384,
	Label:       "SHA-384",
}

var hashSHA512 = Definition{
	Type:        "sha512",
	Description: "Hash SHA-512",
	DataType:    SHA512,
	Label:       "SHA-512",
}

var hashSHA3224 = Definition{
	Type:        "sha3-224",
	Description: "Hash SHA3-224",
	DataType:    SHA3_224,
	Label:       "SHA3-224",
}

var hashSHA3256 = Definition{
	Type:        "sha3-256",
	Description: "Hash SHA3-256",
	DataType:    SHA3_256,
	Label:       "SHA3-256",
}

var hashSHA3384 = Definition{
	Type:        "sha3-384",
	Description: "Hash SHA3-384",
	DataType:    SHA3_384,
	Label:       "SHA3-384",
}

var hashSHA3512 = Definition{
	Type:        "sha3-512",
	Description: "Hash SHA3-512",
	DataType:    SHA3_512,
	Label:       "SHA3-512",
}

var hashSHA512224 = Definition{
	Type:        "sha512-224",
	Description: "Hash SHA512-224",
	DataType:    SHA512_224,
	Label:       "SHA512-224",
}

var hashSHA512256 = Definition{
	Type:        "sha512-256",
	Description: "Hash SHA512-256",
	DataType:    SHA512_256,
	Label:       "SHA512-256",
}

var sshFingerprint = Definition{
	Type:        "ssh-fingerprint",
	Description: "A fingerprint of SSH key material",
	DataType:    STR,
	Label:       "SSH Fingerprint",
}

var ssr = Definition{
	Type:        "ssr",
	Description: "A Special Service Request is a function to an airline to provide a particular facility for A Passenger or passengers",
	DataType:    STR,
	Label:       "Special Service Request",
}

var category = Definition{
	Type:        "category",
	Description: "A category",
	DataType:    ISTR,
	Label:       "Category",
}

var threat = Definition{
	Type:        "threat",
	Description: "A threat",
	DataType:    ISTR,
	Label:       "Threat",
}

var tikTokProfile = Definition{
	Type:        "tiktok-profile",
	Description: "TikTok user profile",
	DataType:    URL,
	Label:       "TikTok Profile",
}

var twitterProfile = Definition{
	Type:        "twitter-profile",
	Description: "A Twitter/X user profile",
	DataType:    URL,
	Label:       "Twitter/X Profile",
}

var uri = Definition{
	Type:        "url",
	Description: "URL",
	DataType:    URL,
	Label:       "URL",
}

var username = Definition{
	Type:        "username",
	Description: "Username",
	DataType:    ISTR,
	Label:       "Username",
}

var visa = Definition{
	Type:        "visa",
	Description: "Traveler visa number",
	DataType:    STR,
	Label:       "Visa Number",
}

var whoIsRegistrant = Definition{
	Type:        "whois-registrant",
	Description: "Who is registrant",
	DataType:    ISTR,
	Label:       "Registrant",
}

var whoIsRegistrar = Definition{
	Type:        "whois-registrar",
	Description: "whois-registrar",
	DataType:    ISTR,
	Label:       "Registrar",
}

var windowsScheduledTask = Definition{
	Type:        "windows-scheduled-task",
	Description: "A Windows scheduled task",
	DataType:    ISTR,
	Label:       "Scheduled Task",
}

var windowsServiceDisplayName = Definition{
	Type:        "windows-service-displayname",
	Description: "A windows service’s displayname, not to be confused with the windows-service-name. This is the name that applications will generally display as the service’s name in applications",
	DataType:    ISTR,
	Label:       "Service Display Name",
}

var windowsServiceName = Definition{
	Type:        "windows-service-name",
	Description: "A windows service name. This is the name used internally by windows. Not to be confused with the windows-service-displayname",
	DataType:    ISTR,
	Label:       "Service Name",
}

var xmr = Definition{
	Type:        "xmr",
	Description: "Monero address",
	DataType:    STR,
	Label:       "Monero Address",
}

var x509MD5 = Definition{
	Type:        "x509-fingerprint-md5",
	Description: "x509 fingerprint in MD5",
	DataType:    MD5,
	Label:       "x509 Fingerprint (MD5)",
}

var x509SHA1 = Definition{
	Type:        "x509-fingerprint-sha1",
	Description: "x509 fingerprint in SHA-1",
	DataType:    SHA1,
	Label:       "x509 Fingerprint (SHA-1)",
}

var x509SHA256 = Definition{
	Type:        "x509-fingerprint-sha256",
	Description: "x509 fingerprint in SHA-256",
	DataType:    SHA256,
	Label:       "x509 Fingerprint (SHA-256)",
}

var breach = Definition{
	Type:        "breach",
	Description: "Security breach that resulted in a leak of PII or SPII",
	DataType:    UUID,
	Attributes:  []Definition{domain, link, breachDate, breachCount, breachDescription},
	Label:       "Breach",
}

var breachDate = Definition{
	Type:        "breach-date",
	Description: "Day the breach occurred",
	DataType:    DATE,
	Label:       "Breach Date",
}

var breachCount = Definition{
	Type:        "breach-count",
	Description: "Number of items leaked in the breach",
	DataType:    INTEGER,
	Label:       "Breach Count",
}

var breachDescription = Definition{
	Type:        "breach-description",
	Description: "Detailed description of the breach",
	DataType:    STR,
	Label:       "Breach Description",
}

var postalAddress = Definition{
	Type:        "postal-address",
	Description: "Postal address",
	DataType:    ISTR,
	Label:       "Postal Address",
}

var zipCode = Definition{
	Type:        "zip-code",
	Description: "Zip code",
	DataType:    STR,
	Label:       "Zip Code",
}

var port = Definition{
	Type:        "port",
	Description: "TCP/UDP Port",
	DataType:    ISTR,
	Label:       "Port",
}

var os = Definition{
	Type:        "os",
	Description: "Operating System",
	DataType:    ISTR,
	Label:       "Operating System",
}

var command = Definition{
	Type:        "command",
	Description: "A cli command",
	DataType:    STR,
	Attributes:  []Definition{os},
	Label:       "Command",
}

var Definitions = []Definition{
	command,
	os,
	port,
	zipCode,
	postalAddress,
	breach,
	breachDate,
	breachCount,
	breachDescription,
	file,
	fileData,
	lastAnalysis,
	adversary,
	aso,
	asn,
	malware,
	malwareFamily,
	malwareType,
	malwareSample,
	abaRtn,
	latitude,
	longitude,
	country,
	cookie,
	text,
	value,
	issuer,
	password,
	airport,
	profilePhoto,
	authentiHash,
	bankAccountNr,
	bic,
	bin,
	btc,
	ccNumber,
	cdHash,
	certificateFingerprint,
	chromeExtension,
	subnet,
	cpe,
	cve,
	dash,
	dkim,
	dkimSignature,
	domain,
	city,
	issuingCountry,
	emailAddress,
	emailBody,
	emailDisplayName,
	emailHeader,
	emailMimeBoundary,
	emailSubject,
	emailThreadIndex,
	emailXMailer,
	email,
	eppn,
	facebookProfile,
	ffn,
	filename,
	sizeInBytes,
	filenamePattern,
	flight,
	gitHubOrganization,
	gitHubRepository,
	gitHubUser,
	link,
	datetime,
	date,
	dateOfIssue,
	expirationDate,
	group,
	haSSHMD5,
	haSSHServerMD5,
	hexa,
	base64d,
	hostname,
	iban,
	idNumber,
	ipAddr,
	ja3Fingerprint,
	jabberID,
	jarmFingerprint,
	macAddr,
	hashMD5,
	mimeType,
	mobileAppID,
	passport,
	pathD,
	patternInFile,
	patternInMemory,
	patternInTraffic,
	pgpPrivateKey,
	pgpPublicKey,
	phone,
	pnr,
	process,
	processState,
	pRtn,
	redress,
	regKey,
	hashSHA1,
	hashSHA224,
	hashSHA256,
	hashSHA384,
	hashSHA512,
	hashSHA3224,
	hashSHA3256,
	hashSHA3384,
	hashSHA3512,
	hashSHA512224,
	hashSHA512256,
	sshFingerprint,
	ssr,
	category,
	threat,
	tikTokProfile,
	twitterProfile,
	uri,
	username,
	visa,
	whoIsRegistrant,
	whoIsRegistrar,
	windowsScheduledTask,
	windowsServiceDisplayName,
	windowsServiceName,
	xmr,
	x509MD5,
	x509SHA1,
	x509SHA256,
	payload,
}
