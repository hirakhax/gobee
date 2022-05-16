package main

import (
	"github.com/gofiber/fiber/v2"
	"github.com/hirakhax/gobee/controllers"
	"github.com/hirakhax/gobee/database"
)

func main() {
	database.ConnectDB()

	app := fiber.New()

	app.Get("/users", controllers.ListUsers)
	app.Post("/users", controllers.CreateUser)

	// Get accessToken & refreshToken
	app.Post("/tokens", controllers.CreateTokens)

	// Get Public Key
	app.Get("/key", controllers.GetKey)

	app.Listen(":3000")
}
