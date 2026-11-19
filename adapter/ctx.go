package adapter

import "context"

type denyKey struct{}

func WithDenyPrivate(ctx context.Context) context.Context {
	return context.WithValue(ctx, denyKey{}, true)
}

func DenyPrivate(ctx context.Context) bool {
	v, _ := ctx.Value(denyKey{}).(bool)
	return v
}

type Group interface {
	Outbound
	Members() []Outbound
	Now() string
}

type Selector interface {
	Group
	Select(tag string) error
}
