package meta

// MetadataStorer defines the interface for managing metadata.
// When object == "", the operation is on the bucket.
type MetadataStorer interface {
	// RetrieveAttribute retrieves the value of a specific attribute for an object or a bucket.
	// Returns the value of the attribute, or an error if the attribute does not exist.
	RetrieveAttribute(bucket, object, attribute string) ([]byte, error)

	// StoreAttribute stores the value of a specific attribute for an object or a bucket.
	// If attribute already exists, new attribute should replace existing.
	// Returns an error if the operation fails.
	StoreAttribute(bucket, object, attribute string, value []byte) error

	// DeleteAttribute removes the value of a specific attribute for an object or a bucket.
	// Returns an error if the operation fails.
	DeleteAttribute(bucket, object, attribute string) error

	// ListAttributes lists all attributes for an object or a bucket.
	// Returns list of attribute names, or an error if the operation fails.
	ListAttributes(bucket, object string) ([]string, error)

	// DeleteAttributes removes all attributes for an object or a bucket.
	// Returns an error if the operation fails.
	DeleteAttributes(bucket, object string) error
}
