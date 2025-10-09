package utils

import (
	"fmt"
	"hash/fnv"
	"reflect"
	"sort"
	"strings"
	"unsafe"
)

func ToString(val any) string {
	switch val := val.(type) {
	case string:
		return val
	case []byte:
		return FromByte(val)
	case nil:
		return ""
	case fmt.Stringer:
		return val.String()
	default:
		return fmt.Sprintf("%v", val)
	}
}

func ToInt64(s string) uint64 {
	ft := fnv.New64()
	_, _ = ft.Write([]byte(s))
	return ft.Sum64()
}

// MatchResource checks if the given value ("METHOD URI" or just a resource/action string)
// matches the provided pattern. Patterns may include:
//   - Wildcard '*' which matches any sequence of characters (including none).
//   - Parameter prefix ':' (e.g., ':id') matching any segment until '/'.
//
// If the value contains an HTTP method (space as separator), both method and URI are matched.
func MatchResource(value, pattern string) bool {
	// Split out HTTP method if present
	valParts := strings.SplitN(value, " ", 2)
	patParts := strings.SplitN(pattern, " ", 2)

	// If pattern includes a method, require it
	if len(patParts) == 2 {
		if len(valParts) != 2 {
			return false
		}
		// Special case for wildcard
		if patParts[0] == "*" && patParts[1] == "*" {
			return true
		}
		if patParts[0] != "*" && valParts[0] != patParts[0] {
			return false
		}
		// Match URI part
		return matchPattern(valParts[1], patParts[1])
	}
	return matchPattern(value, pattern)
}

// matchPattern matches a plain value against a pattern containing
// '*' wildcards and ':' parameters. Parameters match until the next '/'.
// Enhanced to support hierarchical resources.
func matchPattern(value, pattern string) bool {
	vIndex, pIndex := 0, 0
	vLen, pLen := len(value), len(pattern)

	for pIndex < pLen {
		switch pattern[pIndex] {
		case '*':
			// '*' matches any sequence; if it's last, accept
			if pIndex == pLen-1 {
				return true
			}
			// Match until next '/' or end of value
			for vIndex < vLen && value[vIndex] != '/' {
				vIndex++
			}
			pIndex++
		case ':':
			// Skip pattern until end of param name
			pIndex++
			for pIndex < pLen && pattern[pIndex] != '/' {
				pIndex++
			}
			// Skip value until next '/'
			for vIndex < vLen && value[vIndex] != '/' {
				vIndex++
			}
		default:
			// Match literal char
			if vIndex < vLen && pattern[pIndex] == value[vIndex] {
				vIndex++
				pIndex++
			} else {
				return false
			}
		}
	}

	// Both fully consumed?
	// Add support for hierarchical wildcards
	if strings.HasSuffix(pattern, "/*") {
		return strings.HasPrefix(value, strings.TrimSuffix(pattern, "/*"))
	}
	return vIndex == vLen && pIndex == pLen
}

// ToByte converts a string to a byte slice without memory allocation.
// NOTE: The returned byte slice MUST NOT be modified since it shares the same backing array
// with the given string.
func ToByte(s string) []byte {
	p := unsafe.StringData(s)
	b := unsafe.Slice(p, len(s))
	return b
}

// FromByte converts bytes to a string without memory allocation.
// NOTE: The given bytes MUST NOT be modified since they share the same backing array
// with the returned string.
func FromByte(b []byte) string {
	// Ignore if your IDE shows an error here; it's a false positive.
	p := unsafe.SliceData(b)
	return unsafe.String(p, len(b))
}

func Compact(slice []any) []any {
	keys := make(map[any]struct{})
	result := []any{}
	for _, item := range slice {
		if _, exists := keys[item]; !exists {
			keys[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func Contains(slice []interface{}, elem interface{}) bool {
	for _, v := range slice {
		if v == elem {
			return true
		}
	}
	return false
}

func Intersection[T any](a, b []T) []T {
	set := make(map[string]struct{})
	var intersection []T

	for _, item := range a {
		set[Serialize(item)] = struct{}{}
	}

	for _, item := range b {
		if _, exists := set[Serialize(item)]; exists {
			intersection = append(intersection, item)
		}
	}

	return intersection
}

func Union[T any](a, b []T) []T {
	set := make(map[string]struct{})
	var union []T

	for _, item := range a {
		set[Serialize(item)] = struct{}{}
		union = append(union, item)
	}

	for _, item := range b {
		if _, exists := set[Serialize(item)]; !exists {
			union = append(union, item)
		}
	}

	return union
}

func Serialize[T any](item T) string {
	v := reflect.ValueOf(item)
	if v.Kind() == reflect.Map {
		keys := v.MapKeys()
		sort.Slice(keys, func(i, j int) bool {
			return keys[i].String() < keys[j].String()
		})
		var builder strings.Builder
		for _, k := range keys {
			builder.WriteString(fmt.Sprintf("%s:%v|", k, v.MapIndex(k)))
		}
		return builder.String()
	}

	var builder strings.Builder
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		builder.WriteString(fmt.Sprintf("%s:%v|", t.Field(i).Name, v.Field(i).Interface()))
	}

	return builder.String()
}
