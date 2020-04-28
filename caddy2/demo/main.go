package main

import (
	"context"
	"log"

	"github.com/caddyserver/xcaddy"
)

func main() {
	ctx := context.Background()
	builder := xcaddy.Builder{
		CaddyVersion: "v2.0.0-rc.3",
		Plugins: []xcaddy.Dependency{
			{
				ModulePath: "github.com/tarent/loginsrv/caddy2",
			},
		},
	}

	if err := builder.Build(ctx, "./caddy"); err != nil {
		log.Fatalf("error building: %+v", err)
	}
}
