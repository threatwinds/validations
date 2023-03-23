package validations

import (
	"net/http"

	"github.com/quantfall/rerror"
	"google.golang.org/grpc/codes"
)

func ValidateValue(value interface{}, t string) (interface{}, string, *rerror.Error) {
	for _, def := range Kinds {
		if def.Type == t {
			switch def.DataType {
			case STR:
				return ValidateString(value, false)
			case ISTR:
				return ValidateString(value, true)
			case IP:
				return ValidateIP(value)
			case EMAIL:
				return ValidateEmail(value)
			case DOMAIN:
				return ValidateHostOrDomain(value)
			case INTEGER:
				return ValidateInteger(value)
			case CIDR:
				return ValidateCIDR(value)
			case CITY:
				return ValidateCity(value)
			case COUNTRY:
				return ValidateCountry(value)
			case FLOAT:
				return ValidateFloat(value)
			case BOOLEAN:
				return ValidateBoolean(value)
			case URL:
				return ValidateURL(value)
			case MD5:
				return ValidateMD5(value)
			case HEXADECIMAL:
				return ValidateHexadecimal(value)
			case BASE64:
				return ValidateBase64(value)
			case HOSTNAME:
				return ValidateHostOrDomain(value)
			case DATE:
				return ValidateDate(value)
			case MAC:
				return ValidateMAC(value)
			case MIME:
				return ValidateMime(value)
			case PHONE:
				return ValidatePhone(value)
			case SHA1:
				return ValidateSHA1(value)
			case SHA224:
				return ValidateSHA224(value)
			case SHA256:
				return ValidateSHA256(value)
			case SHA384:
				return ValidateSHA384(value)
			case SHA512:
				return ValidateSHA512(value)
			case SHA3_224:
				return ValidateSHA3224(value)
			case SHA3_256:
				return ValidateSHA3256(value)
			case SHA3_384:
				return ValidateSHA3384(value)
			case SHA3_512:
				return ValidateSHA3512(value)
			case SHA512_224:
				return ValidateSHA512224(value)
			case SHA512_256:
				return ValidateSHA512256(value)
			case DATETIME:
				return ValidateDatetime(value)
			case UUID:
				return ValidateUUID(value)
			default:
				return nil, "", rerror.ErrorF(http.StatusInternalServerError, codes.Internal, "unknown validator for value: %v", value)
			}
		}
	}
	return nil, "", rerror.ErrorF(http.StatusBadRequest, codes.InvalidArgument, "unknown kind: %s", t)
}
