package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	db "utils/database"

	"google.golang.org/grpc"

	"proto/out"

	"utils/security/authentication"
	ucrypto "utils/security/crypto"
	"utils/security/hash"
)

var (
	keysPassword      = os.Getenv("KEYS_PASSWORD")
	apiPublicKey      = ucrypto.LoadPublicKey("API_PUBLIC_KEY")
	backendPrivateKey = ucrypto.LoadPrivateKey("BACKEND_PRIVATE_KEY", keysPassword)
)

type AuthenticationProto struct {
	out.UnimplementedAuthenticationServer
}

func (ap *AuthenticationProto) AuthenticateLogin(ctx context.Context, req *out.Login) (*out.Token, error) {
	var token string
	email := req.GetEmail()
	password := req.GetPassword()
	decodedDecryptedEmail := ucrypto.DecodeDecrypt(backendPrivateKey, email)
	decodedDecryptedPassword := ucrypto.DecodeDecrypt(backendPrivateKey, password)

	user := db.GetUserByEmail(string(decodedDecryptedEmail))
	if user != nil {
		log.Println("USER EXISTS")
		log.Println("USER", user.Email)
		log.Println("USER", user.Password)
		log.Println("USER", user.FirstName)
		log.Println("USER", user.LastName)
		log.Println(string(decodedDecryptedPassword))
		if hash.CheckPasswordHash(string(decodedDecryptedPassword), user.Password) {
			log.Println("PASSWORD MATCH")
			token = authentication.NewJWTToken(user.Password, fmt.Sprintf("%d", user.ID), 24)
			log.Println(token)
		}
	}
	// if user != nil && hash.CheckPasswordHash(string(decodedDecryptedPassword), user.Password) {
		// token = authentication.NewJWTToken(user.Password, fmt.Sprintf("%d", user.ID), 24)
		// log.Println("INSIDE IF CHECK", token)
	// }

	log.Println(user.Email)
	log.Println(token)
	encodedEncryptedToken := ucrypto.EncryptEncode(apiPublicKey, []byte(token))

	return &out.Token{Token: encodedEncryptedToken}, nil
}

func (ap *AuthenticationProto) AuthenticateSignUp(ctx context.Context, req *out.SignUp) (*out.Token, error) {
	email := req.GetEmail()
	password := req.GetPassword()
	firstName := req.GetFirstName()
	lastName := req.GetLastName()
	decodedDecryptedEmail := ucrypto.DecodeDecrypt(backendPrivateKey, email)
	decodedDecryptedPassword := ucrypto.DecodeDecrypt(backendPrivateKey, password)
	decodedDecryptedFirstName := ucrypto.DecodeDecrypt(backendPrivateKey, firstName)
	decodedDecryptedLastName := ucrypto.DecodeDecrypt(backendPrivateKey, lastName)


	userAuthToken := db.CreateNewUser(
		string(decodedDecryptedEmail), 
		string(decodedDecryptedPassword), 
		string(decodedDecryptedFirstName), 
		string(decodedDecryptedLastName),
	)

	log.Println(userAuthToken)

	encodedEncryptedToken := ucrypto.EncryptEncode(apiPublicKey, []byte(userAuthToken))

	return &out.Token{Token: encodedEncryptedToken}, nil
}

func init() {
	db.MigrateDatabase()
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	out.RegisterAuthenticationServer(s, &AuthenticationProto{})
	log.Printf("server listening at %v", lis.Addr())

	t, _ := hash.HashPassword("test")
	log.Println(t)

	if hash.CheckPasswordHash("test", t) {
		log.Println("HASH IS WORKING")
		log.Println(t)
	}

	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
