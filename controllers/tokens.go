package controllers

import (
	"crypto/rsa"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"github.com/hirakhax/gobee/database"
	"github.com/hirakhax/gobee/models"
	"golang.org/x/crypto/bcrypt"
)

type LoginInputSerializer struct {
	Username string
	Password string
}

type LoginOutputSerializer struct {
	AccessToken  string
	RefreshToken string
}

type JWTClaims struct {
	Sub string `json:"sub,omitempty"`
	jwt.StandardClaims
}

type SigningKeys struct {
	Private []byte
	Public  []byte
}

func (keys *SigningKeys) loadPrivate() error {
	bytes, err := os.ReadFile("certs/private.pem")
	if err != nil {
		return err
	}
	keys.Private = bytes
	return nil
}

func (keys *SigningKeys) loadPublic() error {
	bytes, err := os.ReadFile("certs/public.pem")
	if err != nil {
		return err
	}
	keys.Public = bytes
	return nil
}

func generateAccessToken(sub string, key *rsa.PrivateKey, outputSerializer *LoginOutputSerializer) error {
	accessTokenClaims := &JWTClaims{
		Sub: sub,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		},
	}
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, accessTokenClaims).SignedString(key)
	if err != nil {
		return err
	}

	outputSerializer.AccessToken = accessToken
	return nil
}

func generateRefreshToken(sub string, key *rsa.PrivateKey, outputSerializer *LoginOutputSerializer) error {
	refreshTokenClaims := &JWTClaims{
		Sub: sub,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(720 * time.Hour).Unix(),
		},
	}
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshTokenClaims).SignedString(key)
	if err != nil {
		return err
	}

	outputSerializer.RefreshToken = refreshToken
	return nil
}

func CreateTokens(c *fiber.Ctx) error {
	var loginSerializer LoginInputSerializer
	var outputSerializer LoginOutputSerializer
	var signingKeys SigningKeys

	if err := c.BodyParser(&loginSerializer); err != nil {
		return err
	}

	var user models.User
	tx := database.Db.First(&user, "username = ?", loginSerializer.Username)

	if tx.RowsAffected == 0 {
		return c.Status(400).JSON(fiber.Map{
			"message": "Wrong credentials",
		})
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginSerializer.Password))
	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"message": "Password not matched",
		})
	}

	if err := signingKeys.loadPrivate(); err != nil {
		return err
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(signingKeys.Private)
	if err != nil {
		return err
	}

	userId := strconv.FormatUint(uint64(user.ID), 10)

	if err := generateAccessToken(userId, key, &outputSerializer); err != nil {
		return err
	}

	if err := generateRefreshToken(userId, key, &outputSerializer); err != nil {
		return err
	}

	return c.JSON(outputSerializer)
}

func GetKey(c *fiber.Ctx) error {
	var signinKeys SigningKeys
	if err := signinKeys.loadPublic(); err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"key": strings.ReplaceAll(string(signinKeys.Public), "\n", ""),
	})
}
