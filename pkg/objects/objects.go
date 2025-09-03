package objects

import (
	"github.com/gofiber/fiber/v2"

	"github.com/oarkflow/auth/pkg/contracts"
)

var (
	Manager    contracts.Manager
	Config     contracts.Config
	ViewEngine fiber.Views
	Layout     string
)
