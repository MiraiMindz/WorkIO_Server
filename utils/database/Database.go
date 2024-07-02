package database

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	auth "utils/security/authentication"
	ucrypto "utils/security/crypto"
	uhash "utils/security/hash"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Email     string
	Password  string
	FirstName string
	LastName  string
}

const (
	database_path = "database/database.db"
	AESGCMKEY = "I0qSbnp03rYWzQaESaXqZkoRCrEhFOdK"
)

var (
	keysPassword       = os.Getenv("KEYS_PASSWORD")
	databasePublicKey  = ucrypto.LoadPublicKey("DATABASE_PUBLIC_KEY")
	databasePrivateKey = ucrypto.LoadPrivateKey("DATABASE_PRIVATE_KEY", keysPassword)
)

func checkFileExists(filePath string) bool {
	_, error := os.Stat(filePath)
	//return !os.IsNotExist(err)
	return !errors.Is(error, os.ErrNotExist)
}

func getDatabasePath() string {
	d, _ := os.Getwd()
	fpath := make([]string, 0)
	fpath = append(fpath, d)
	fpath = append(fpath, strings.Split(database_path, "/")...)
	p := filepath.Join(fpath...)
	return p
}

func MigrateDatabase() {
	dbPath := getDatabasePath()
	if !checkFileExists(dbPath) {
		db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
		if err != nil {
			log.Fatalln(err.Error())
		}

		db.AutoMigrate(&User{})
		db.Commit()
	}

}

func CreateNewUser(email, password, firstName, lastName string) string {
	dbPath := getDatabasePath()
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		log.Fatalln(err.Error())
	}

	hashedPassword, err := uhash.HashPassword(password)
	if err != nil {
		log.Fatalln(err.Error())
	}

	addUser := User{
		Email:     ucrypto.EncodeBase64([]byte(email)),
		Password:  ucrypto.EncodeBase64([]byte(hashedPassword)),
		FirstName: ucrypto.EncodeBase64([]byte(firstName)),
		LastName:  ucrypto.EncodeBase64([]byte(lastName)),
	}

	result := db.Create(&addUser)

	if result.Error != nil {
		return ""
	}

	if addUser.ID == 0 {
		return ""
	}

	userToken := auth.NewJWTToken(hashedPassword, fmt.Sprintf("%d", addUser.ID), 24)
	db.Commit()
	return userToken
}

func GetUserByID(userID uint) *User {
	dbPath := getDatabasePath()
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		log.Fatalln(err.Error())
	}
	var foundEncryptedUser User
	result := db.First(&foundEncryptedUser, userID)
	if result.Error != nil {
		return nil
	}

	db.Commit()

	return &User{
		Model:     foundEncryptedUser.Model,
		Email:     string(ucrypto.DecodeBase64(foundEncryptedUser.Email)),
		Password:  string(ucrypto.DecodeBase64(foundEncryptedUser.Password)),
		FirstName: string(ucrypto.DecodeBase64(foundEncryptedUser.FirstName)),
		LastName:  string(ucrypto.DecodeBase64(foundEncryptedUser.LastName)),
	}
}

func GetUserByEmail(email string) *User {
	dbPath := getDatabasePath()
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		log.Fatalln(err.Error())
	}
	var foundEncryptedUser User
	// result := db.First(&foundEncryptedUser, "email = ?", email)
	result := db.Where("email = ?", ucrypto.EncodeBase64([]byte(email))).First(&foundEncryptedUser)
	if result.Error != nil {
		return nil
	}

	log.Println(string(ucrypto.DecodeBase64(foundEncryptedUser.Email)))

	db.Commit()
	return &User{
		Model:     foundEncryptedUser.Model,
		Email:     string(ucrypto.DecodeBase64(foundEncryptedUser.Email)),
		Password:  string(ucrypto.DecodeBase64(foundEncryptedUser.Password)),
		FirstName: string(ucrypto.DecodeBase64(foundEncryptedUser.FirstName)),
		LastName:  string(ucrypto.DecodeBase64(foundEncryptedUser.LastName)),
	}
}
