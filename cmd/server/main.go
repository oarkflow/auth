package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gookit/color"
	"github.com/knadh/koanf/parsers/dotenv"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"

	"github.com/oarkflow/squealx"
	"github.com/oarkflow/squealx/connection"

	v2 "github.com/oarkflow/auth"
	"github.com/oarkflow/auth/pkg/config"
	"github.com/oarkflow/auth/pkg/libs"
	"github.com/oarkflow/auth/pkg/objects"
)

func main() {
	objects.Config = New(".env", true, nil)
	cfg := config.Config{}
	cfg.Load()
	objects.Layout = "layouts/main"
	app := fiber.New(fiber.Config{
		ViewsLayout: objects.Layout,
	})
	dbConfig := squealx.Config{
		Driver:   "postgres",
		Host:     "localhost",
		Port:     5432,
		Username: "postgres",
		Password: "postgres",
		Database: "communities",
	}
	db, _, err := connection.FromConfig(dbConfig)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	authPlugin := v2.NewPluginWithOptions(
		v2.WithPrefix("/"),
		v2.WithLoginSuccessURL("/app"),
		v2.WithNotificationHandler(libs.NotificationHandler{}),
		v2.WithApp(app),
		v2.WithDB(db),
		v2.WithDBReset(true),
	)
	authPlugin.Register()
	if err := app.Listen(":3000"); err != nil {
		log.Fatal(err)
	}
}

type Config struct {
	k *koanf.Koanf
}

// New initializes a new config instance.
func New(envPath string, watchEnv bool, callback func()) *Config {
	k := koanf.New(".")
	app := &Config{k: k}
	f := file.Provider(envPath)
	// Load configuration from .env file if it exists
	if _, err := os.Stat(envPath); err == nil {
		if err := app.k.Load(f, dotenv.Parser()); err != nil {
			color.Red.Println("Error loading .env file: " + err.Error())
			os.Exit(0)
		}
	} else {
		color.Red.Println("No .env file found at " + envPath)
	}

	// Load environment variables
	if err := app.k.Load(env.Provider("", ".", nil), nil); err != nil {
		color.Red.Println("Error loading environment variables: " + err.Error())
		os.Exit(0)
	}
	if watchEnv {
		f.Watch(func(event interface{}, err error) {
			if err != nil {
				log.Printf("watch error: %v", err)
				return
			}
			if callback != nil {
				callback()
			}
		})
	}
	return app
}

// Env retrieves a config value from the environment with an optional default.
func (app *Config) Env(envName string, defaultValue ...any) any {
	value := app.k.Get(envName)
	if value == nil {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}
		return nil
	}
	return value
}

// Add adds a configuration to the application.
func (app *Config) Add(name string, configuration any) {
	err := app.k.Set(name, configuration)
	if err != nil {
		panic(err)
	}
}

// Get retrieves a config value from the application.
func (app *Config) Get(path string, defaultValue ...any) any {
	value := app.k.Get(path)
	if value == nil {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}
		return nil
	}
	return value
}

// GetString retrieves a string type config value from the application.
func (app *Config) GetString(path string, defaultValue ...any) string {
	value := app.Get(path, defaultValue...)
	if strVal, ok := value.(string); ok {
		return strVal
	}
	if len(defaultValue) > 0 {
		return fmt.Sprintf("%v", defaultValue[0])
	}
	return ""
}

// GetInt retrieves an int type config value from the application.
func (app *Config) GetInt(path string, defaultValue ...any) int {
	value := app.Get(path, defaultValue...)
	switch v := value.(type) {
	case int:
		return v
	case string:
		if intVal, err := strconv.Atoi(v); err == nil {
			return intVal
		}
	}
	if len(defaultValue) > 0 {
		return defaultValue[0].(int)
	}
	return 0
}

func (app *Config) GetDuration(path string, defaultValue ...any) time.Duration {
	value := app.Get(path, defaultValue...)
	if duration, ok := value.(time.Duration); ok {
		return duration
	}
	if strVal, ok := value.(string); ok {
		if duration, err := time.ParseDuration(strVal); err == nil {
			return duration
		}
	}
	if len(defaultValue) > 0 {
		dur := defaultValue[0]
		switch d := dur.(type) {
		case time.Duration:
			return d
		case string:
			if duration, err := time.ParseDuration(d); err == nil {
				return duration
			}
		}
	}
	return 0
}

// GetBool retrieves a bool type config value from the application.
func (app *Config) GetBool(path string, defaultValue ...any) bool {
	value := app.Get(path, defaultValue...)
	switch v := value.(type) {
	case bool:
		return v
	case string:
		if boolVal, err := strconv.ParseBool(v); err == nil {
			return boolVal
		}
	}
	if len(defaultValue) > 0 {
		return defaultValue[0].(bool)
	}
	return false
}
