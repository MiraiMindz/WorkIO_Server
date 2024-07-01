package main

import (
	"context"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"

	"proto/out"

	ucrypto "utils/security/crypto"
)

var (
	keysPassword = os.Getenv("KEYS_PASSWORD")
	apiPublicKey = ucrypto.LoadPublicKey("API_PUBLIC_KEY")
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

	if string(decodedDecryptedEmail) == "" && string(decodedDecryptedPassword) == "" {
		token = "AUTHENTICATED"
	} else {
		token = "UNAUTHORIZED"
	}

	encryptedToken := ucrypto.Encrypt(apiPublicKey, []byte(token))
	encodedToken := ucrypto.EncodeBase64(encryptedToken)


	return &out.Token{Token: encodedToken}, nil
}

func main()  {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	out.RegisterAuthenticationServer(s, &AuthenticationProto{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}