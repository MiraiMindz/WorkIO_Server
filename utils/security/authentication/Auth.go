package authentication

import (
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTClaims struct {
	jwt.RegisteredClaims
}

func NewJWTToken(signingKey string, subject string, expirationTimeInHours time.Duration) string {
	signKey := []byte(signingKey)

	claims := JWTClaims{
		jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expirationTimeInHours * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "WorkIO",
			Subject:   subject,
			// ID:        fmt.Sprintf("%d", user.ID),
		},
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	signedString, err := jwtToken.SignedString(signKey)
	if err != nil {
		log.Fatalln(err.Error())
	}

	return signedString
}

func ParseJWTToken(token, signingKey string) (*JWTClaims) {
	parsedToken, err := jwt.ParseWithClaims(token, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(signingKey), nil
	})

	if err != nil {
		log.Fatalln(err.Error())
		return nil
	} 

	parsedClaims := parsedToken.Claims.(*JWTClaims)
	
	return parsedClaims
}
