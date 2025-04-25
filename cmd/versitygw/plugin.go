package main

import (
	"errors"
	"fmt"
	"plugin"

	"github.com/urfave/cli/v2"
	"github.com/versity/versitygw/plugins"
)

func pluginCommand() *cli.Command {
	return &cli.Command{
		Name:        "plugin",
		Usage:       "load a backend from a plugin",
		Description: "Runs a s3 gateway and redirects the requests to the backend defined in the plugin",
		Action:      runPluginBackend,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Usage:   "location of the config file",
				Aliases: []string{"c"},
			},
		},
	}
}

func runPluginBackend(ctx *cli.Context) error {
	if ctx.NArg() == 0 {
		return fmt.Errorf("no plugin file provided to be loaded")
	}

	pluginPath := ctx.Args().Get(0)
	config := ctx.String("config")

	p, err := plugin.Open(pluginPath)
	if err != nil {
		return err
	}

	backendSymbol, err := p.Lookup("Backend")
	if err != nil {
		return err
	}
	backendPluginPtr, ok := backendSymbol.(*plugins.BackendPlugin)
	if !ok {
		return errors.New("plugin is not of type *plugins.BackendPlugin")
	}

	if backendPluginPtr == nil {
		return errors.New("variable Backend is nil")
	}

	be, err := (*backendPluginPtr).New(config)
	if err != nil {
		return err
	}

	return runGateway(ctx.Context, be)
}
