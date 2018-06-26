package gimlet

import (
	"encoding/json"
	"net/http"

	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v2"
)

func NewTextResponse(data interface{}) Responder {
	return &responderImpl{
		data:   convertToBytes(data),
		status: http.StatusOK,
		format: TEXT,
	}
}

func NewTextErrorResponse(data interface{}) Responder {
	return &responderImpl{
		data:   convertToBytes(data),
		status: http.StatusBadRequest,
		format: TEXT,
	}
}

func NewTextInternalErrorResponse(data interface{}) Responder {
	return &responderImpl{
		data:   convertToBytes(data),
		status: http.StatusInternalServerError,
		format: TEXT,
	}
}

func getJSONResponseBody(data interface{}) ([]byte, error) {
	out, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, err
	}

	return out, nil
}

func NewJSONResponse(data interface{}) Responder {
	out, err := getJSONResponseBody(data)
	if err != nil {
		return &responderImpl{
			data: ErrorResponse{
				StatusCode: http.StatusInternalServerError,
				Message:    err.Error(),
			},
			status: http.StatusInternalServerError,
			format: JSON,
		}
	}

	return &responderImpl{
		data:   append(out, []byte("\n")...),
		status: http.StatusOK,
		format: JSON,
	}
}

func NewJSONErrorResponse(data interface{}) Responder {
	out, err := getJSONResponseBody(data)
	if err != nil {
		return &responderImpl{
			data: ErrorResponse{
				StatusCode: http.StatusInternalServerError,
				Message:    err.Error(),
			},
			status: http.StatusInternalServerError,
			format: JSON,
		}
	}

	return &responderImpl{
		data:   append(out, []byte("\n")...),
		status: http.StatusBadRequest,
		format: JSON,
	}
}

func NewJSONInternalErrorResponse(data interface{}) Responder {
	out, err := getJSONResponseBody(data)
	if err != nil {
		return &responderImpl{
			data: ErrorResponse{
				StatusCode: http.StatusInternalServerError,
				Message:    err.Error(),
			},
			status: http.StatusInternalServerError,
			format: JSON,
		}
	}

	return &responderImpl{
		data:   append(out, []byte("\n")...),
		status: http.StatusInternalServerError,
		format: JSON,
	}
}

func NewBinaryResponse(data interface{}) Responder {
	return &responderImpl{
		data:   convertToBin(data),
		status: http.StatusOK,
		format: BINARY,
	}
}

func NewBinaryErrorResponse(data interface{}) Responder {
	return &responderImpl{
		data:   convertToBin(data),
		status: http.StatusBadRequest,
		format: BINARY,
	}
}

func NewBinaryInternalErrorResponse(data interface{}) Responder {
	return &responderImpl{
		data:   convertToBin(data),
		status: http.StatusInternalServerError,
		format: BINARY,
	}
}

func NewHTMLResponse(data interface{}) Responder {
	return &responderImpl{
		data:   convertToBytes(data),
		status: http.StatusOK,
		format: HTML,
	}
}

func NewHTMLErrorResponse(data interface{}) Responder {
	return &responderImpl{
		data:   convertToBytes(data),
		status: http.StatusBadRequest,
		format: HTML,
	}
}

func NewHTMLInternalErrorResponse(data interface{}) Responder {
	return &responderImpl{
		data:   convertToBytes(data),
		status: http.StatusInternalServerError,
		format: HTML,
	}
}

func getYAMLResponseBody(data interface{}) (out []byte, err error) {
	defer func() {
		if msg := recover(); msg != nil {
			out = nil
			err = errors.Errorf("problem yaml parsing message: %v", msg)
		}
	}()

	out, err = yaml.Marshal(data)
	return
}

func NewYAMLResponse(data interface{}) Responder {
	out, err := getYAMLResponseBody(data)
	if err != nil {
		return &responderImpl{
			data: ErrorResponse{
				StatusCode: http.StatusInternalServerError,
				Message:    err.Error(),
			},
			status: http.StatusInternalServerError,
			format: YAML,
		}
	}

	return &responderImpl{
		data:   append(out, []byte("\n")...),
		status: http.StatusOK,
		format: YAML,
	}
}

func NewYAMLErrorResponse(data interface{}) Responder {
	out, err := getYAMLResponseBody(data)
	if err != nil {
		return &responderImpl{
			data: ErrorResponse{
				StatusCode: http.StatusInternalServerError,
				Message:    err.Error(),
			},
			status: http.StatusInternalServerError,
			format: YAML,
		}
	}

	return &responderImpl{
		data:   append(out, []byte("\n")...),
		status: http.StatusBadRequest,
		format: YAML,
	}
}

func NewYAMLInternalErrorResponse(data interface{}) Responder {
	out, err := getYAMLResponseBody(data)
	if err != nil {
		return &responderImpl{
			data: ErrorResponse{
				StatusCode: http.StatusInternalServerError,
				Message:    err.Error(),
			},
			status: http.StatusInternalServerError,
			format: YAML,
		}
	}

	return &responderImpl{
		data:   append(out, []byte("\n")...),
		status: http.StatusInternalServerError,
		format: YAML,
	}
}
