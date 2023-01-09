package helper

type KeyTypes string

const (
	RSA     KeyTypes = "RSA"
	ECC     KeyTypes = "ECC"
	UNKNOWN KeyTypes = ""
)

func (k KeyTypes) ToString() string {
	return string(k)
}
