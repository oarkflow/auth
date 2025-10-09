package responses

import (
	"os"
	"reflect"
	"strings"

	"github.com/andeya/goutil"
	"github.com/gofiber/fiber/v2"

	"github.com/oarkflow/auth/pkg/objects"
)

func Render(c *fiber.Ctx, template string, data any, layouts ...string) error {
	if c == nil {
		return fiber.ErrBadRequest
	}
	if template == "" {
		return c.JSON(data)
	}
	layout := "auth/" + objects.Layout
	if len(layouts) > 0 {
		layout = layouts[0]
	}
	if layout != "" {
		layouts = []string{layout}
	}
	c.Set("Content-Type", "text/html; charset=utf-8")
	if objects.ViewEngine == nil {
		return c.Render(template, data, layouts...)
	}

	return objects.ViewEngine.Render(c.Response().BodyWriter(), template, data, layouts...)
}

type Response struct {
	Additional any    `json:"additional,omitempty"`
	Data       any    `json:"data"`
	Message    string `json:"message,omitempty"`
	StackTrace string `json:"stack_trace,omitempty"`
	Code       int    `json:"code"`
	Success    bool   `json:"success"`
}

func getResponse(code int, message string, additional any, stackTrace ...string) Response {
	var trace string
	isDebug := objects.Config.GetBool("app.debug")
	response := Response{
		Code:       code,
		Message:    message,
		Success:    false,
		Additional: additional,
	}

	if len(stackTrace) > 0 && isDebug {
		dir, _ := os.Getwd()
		trace = stackTrace[0]
		trace = strings.ReplaceAll(trace, dir, "/root")
		for _, t := range goutil.GetGopaths() {
			trace = strings.ReplaceAll(trace, t+"pkg/mod/", "/root/")
			trace = strings.ReplaceAll(trace, t, "/root/")
		}
		response.StackTrace = trace
	}
	return response
}

func Abort(ctx *fiber.Ctx, code int, message string, additional any, stackTrace ...string) error {
	return ctx.Status(fiber.StatusOK).JSON(getResponse(code, message, additional, stackTrace...))
}

func Failed(ctx *fiber.Ctx, code int, message string, additional any, stackTrace ...string) error {
	return ctx.Status(fiber.StatusOK).JSON(getResponse(code, message, additional, stackTrace...))
}

func Success(ctx *fiber.Ctx, code int, data any, message ...string) error {
	response := Response{
		Code:    code,
		Data:    ZeroIfNil(data),
		Success: true,
	}
	if len(message) > 0 {
		response.Message = message[0]
	}
	return ctx.Status(fiber.StatusOK).JSON(response)
}

func ZeroIfNil(data any) any {
	if data == nil {
		return nil
	}

	v := reflect.ValueOf(data)
	t := v.Type()

	switch v.Kind() {
	case reflect.Map:
		if v.IsNil() {
			// return an empty map of the same type
			return reflect.MakeMap(t).Interface()
		}
	case reflect.Slice:
		if v.IsNil() {
			// return an empty slice of the same type
			return reflect.MakeSlice(t, 0, 0).Interface()
		}
	}

	return data
}
