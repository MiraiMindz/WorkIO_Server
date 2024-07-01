package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"google.golang.org/grpc"

	"proto/out"

	ucrypto "utils/security/crypto"
)

var (
	keysPassword = os.Getenv("KEYS_PASSWORD")
	apiPublicKey = ucrypto.LoadPublicKey("API_PUBLIC_KEY")
	backendPrivateKey = ucrypto.LoadPrivateKey("BACKEND_PRIVATE_KEY", keysPassword)
)

type TestProto struct {
	out.UnimplementedTestServer
}

func (tp *TestProto) TestFunc(ctx context.Context, req *out.TestRequest) (*out.TestResponse, error) {
	msg := req.GetMessage()
	decodedMessage := ucrypto.DecodeBase64(msg)
	decryptedMessage := ucrypto.Decrypt(backendPrivateKey, decodedMessage)

	res := strings.ToUpper(fmt.Sprintf("Server Response to %s", string(decryptedMessage)))

	encryptedResponse := ucrypto.Encrypt(apiPublicKey, []byte(res))
	encodedResponse := ucrypto.EncodeBase64(encryptedResponse)


	return &out.TestResponse{Message: encodedResponse}, nil
}

func main()  {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	out.RegisterTestServer(s, &TestProto{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}