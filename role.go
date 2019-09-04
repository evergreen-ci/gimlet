package gimlet

// Role is the data structure used to read and manipulate user roles and permissions
type Role struct {
	ID          string         `json:"id" bson:"_id"`
	Name        string         `json:"name" bson:"name,omitempty"`
	ScopeType   string         `json:"scope_type" bson:"scope_type,omitempty"`
	Scope       string         `json:"scope" bson:"scope,omitempty"`
	Permissions map[string]int `json:"permissions" bson:"permissions,omitempty"`
	Owners      []string       `json:"owners" bson:"owners,omitempty"`
}
