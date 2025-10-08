package command

type TagAdder interface {
	AddTag(tag string, value string) error
}
