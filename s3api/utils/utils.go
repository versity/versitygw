// Copyright 2023 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package utils

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

func GetUserMetaData(headers *fasthttp.RequestHeader) (metadata map[string]string) {
	metadata = make(map[string]string)
	headers.VisitAll(func(key, value []byte) {
		if strings.HasPrefix(string(key), "X-Amz-Meta-") {
			trimmedKey := strings.TrimPrefix(string(key), "X-Amz-Meta-")
			headerValue := string(value)
			metadata[trimmedKey] = headerValue
		}
	})

	return
}

func CreateHttpRequestFromCtx(ctx *fiber.Ctx) (*http.Request, error) {
	req := ctx.Request()

	httpReq, err := http.NewRequest(string(req.Header.Method()), req.URI().String(), bytes.NewReader(req.Body()))
	if err != nil {
		return nil, errors.New("error in creating an http request")
	}

	// Set the request headers
	req.Header.VisitAll(func(key, value []byte) {
		keyStr := string(key)
		if keyStr == "X-Amz-Date" || keyStr == "X-Amz-Content-Sha256" || keyStr == "Host" {
			httpReq.Header.Add(keyStr, string(value))
		}
	})

	// Set the Content-Length header
	httpReq.ContentLength = int64(len(req.Body()))

	// Set the Host header
	httpReq.Host = string(req.Header.Host())

	return httpReq, nil
}

func MarshalStructToXML(data interface{}) ([]byte, error) {
	value := reflect.ValueOf(data)
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}

	switch value.Kind() {
	case reflect.Struct:
		xmlData := []byte{}

		for i := 0; i < value.NumField(); i++ {
			field := value.Field(i)
			fieldType := value.Type().Field(i)

			if field.CanInterface() {
				tag := fieldType.Tag.Get("xml")
				if tag == "" {
					tag = fieldType.Name
				}

				if field.Kind() == reflect.Slice {
					for j := 0; j < field.Len(); j++ {
						item := field.Index(j).Interface()
						itemData, err := MarshalStructToXML(item)
						if err != nil {
							return nil, err
						}

						xmlData = append(xmlData, itemData...)
					}
				} else if field.Kind() == reflect.Struct || field.Kind() == reflect.Ptr {
					subData := field.Interface()
					subDataXML, err := MarshalStructToXML(subData)
					if err != nil {
						return nil, err
					}

					openTag := fmt.Sprintf("<%s>", tag)
					closeTag := fmt.Sprintf("</%s>", tag)

					xmlData = append(xmlData, []byte(openTag)...)
					xmlData = append(xmlData, subDataXML...)
					xmlData = append(xmlData, []byte(closeTag)...)
				} else {
					fieldData := fmt.Sprintf("<%s>%v</%s>", tag, field.Interface(), tag)
					xmlData = append(xmlData, []byte(fieldData)...)
				}
			}
		}
		return xmlData, nil

	case reflect.Map:
		xmlData := []byte{}
		iter := value.MapRange()
		for iter.Next() {
			key := iter.Key()
			val := iter.Value()

			subDataXML, err := MarshalStructToXML(val.Interface())
			if err != nil {
				return nil, err
			}

			openTag := fmt.Sprintf("<%v>", key.Interface())
			closeTag := fmt.Sprintf("</%v>", key.Interface())

			xmlData = append(xmlData, []byte(openTag)...)
			xmlData = append(xmlData, subDataXML...)
			xmlData = append(xmlData, []byte(closeTag)...)
		}
		return xmlData, nil

	default:
		return []byte(fmt.Sprintf("%v", data)), nil
	}
}
