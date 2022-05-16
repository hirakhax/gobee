package controllers

import (
	"errors"
	"regexp"

	"github.com/gofiber/fiber/v2"
	"github.com/hirakhax/gobee/database"
	"github.com/hirakhax/gobee/models"
	"golang.org/x/crypto/bcrypt"
)

type UserCreateSerializer struct {
	Username string
	Email    string
	Password string
}

func validateUsername(serializer *UserCreateSerializer) error {
	msg := "Username needs to be under 4 to 20 characters. Also it must not contains any special character and space except underscore(_)"
	if matched, _ := regexp.MatchString("^[a-zA-Z0-1_]{4,20}$", serializer.Username); !matched {
		return errors.New(msg)
	}
	return nil
}

func validateEmail(serializer *UserCreateSerializer) error {
	msg := "Unsupported email address"
	if matched, _ := regexp.MatchString("^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$", serializer.Email); !matched {
		return errors.New(msg)
	}
	return nil
}

func validatePassword(serializer *UserCreateSerializer) error {
	msg := "Password must be under 4 to 20 characters."
	if len(serializer.Password) < 4 || len(serializer.Password) > 20 {
		return errors.New(msg)
	}
	return nil
}

func ListUsers(c *fiber.Ctx) error {
	var users []models.User
	database.Db.Find(&users)
	return c.JSON(users)
}

func CreateUser(c *fiber.Ctx) error {
	var userCreateSerializer UserCreateSerializer

	if err := c.BodyParser(&userCreateSerializer); err != nil {
		return c.Status(400).JSON(fiber.Map{"message": "Invalid body"})
	}

	if err := validateUsername(&userCreateSerializer); err != nil {
		return c.Status(400).JSON(fiber.Map{"message": err.Error()})
	}

	if err := validateEmail(&userCreateSerializer); err != nil {
		return c.Status(400).JSON(fiber.Map{"message": err.Error()})
	}

	if err := validatePassword(&userCreateSerializer); err != nil {
		return c.Status(400).JSON(fiber.Map{"message": err.Error()})
	}

	hashedPass, err := bcrypt.GenerateFromPassword([]byte(userCreateSerializer.Password), 10)
	if err != nil {
		return err
	}

	userCreateSerializer.Password = string(hashedPass)

	var u models.User = models.User{
		Username: userCreateSerializer.Username,
		Email:    userCreateSerializer.Email,
		Password: userCreateSerializer.Password,
	}

	database.Db.Create(&u)

	return c.Status(fiber.StatusCreated).JSON(u)
}
