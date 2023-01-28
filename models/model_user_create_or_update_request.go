package models

import "github.com/Delave-las-Kure/wgrest/db/model"

// UserCreateOrUpdateRequest - User params that might be used due to creation or updation process
type UserCreateOrUpdateRequest struct {

	// User foreign id
	FID *string `json:"fid,omitempty"`

	// Base64 encoded public key
	Name *string `json:"name,omitempty"`
}

func (r *UserCreateOrUpdateRequest) Apply(user *model.User) []string {
	var fields []string

	/*if r.ID != nil {
		user.ID = *r.ID
		fields = append(fields, "ID")
	}*/

	if r.FID != nil {
		user.FID = *r.FID
		fields = append(fields, "FID")
	}

	if r.Name != nil {
		user.Name = *r.Name
		fields = append(fields, "Name")
	}

	return fields
}
