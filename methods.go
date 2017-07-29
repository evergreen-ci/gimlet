package gimlet

type httpMethod int

// Typed constants for specifying HTTP method types on routes.
const (
	get httpMethod = iota
	put
	post
	delete
	patch
)

func (m httpMethod) String() string {
	switch m {
	case get:
		return "get"
	case put:
		return "put"
	case delete:
		return "delete"
	case patch:
		return "patch"
	default:
		return ""
	}
}

type OutputFormat int

const (
	JSON OutputFormat = iota
	TEXT
	HTML
	YAML
	BINARY
)

func (o OutputFormat) IsValid() bool {
	switch o {
	case JSON, TEXT, HTML, BINARY, YAML:
		return true
	default:
		return false
	}
}

func (o OutputFormat) String() string {
	switch o {
	case JSON:
		return "binary"
	case TEXT:
		return "text"
	case HTML:
		return "html"
	case BINARY:
		return "binary"
	case YAML:
		return "yaml"
	default:
		return "text"
	}
}
