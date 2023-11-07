package v1

import (
	"context"
	"fmt"
	"net"

	middlewares "github.com/asians-cloud/crowdsec/pkg/apiserver/middlewares/v1"
	"github.com/asians-cloud/crowdsec/pkg/csconfig"
	"github.com/asians-cloud/crowdsec/pkg/csplugin"
	"github.com/asians-cloud/crowdsec/pkg/csprofiles"
	"github.com/asians-cloud/crowdsec/pkg/database"
	"github.com/asians-cloud/crowdsec/pkg/models"
)

type Controller struct {
	Ectx         context.Context
	DBClient     *database.Client
	APIKeyHeader string
	Middlewares  *middlewares.Middlewares
	Profiles     []*csprofiles.Runtime

	AlertsAddChan      chan []*models.Alert
	DecisionDeleteChan chan []*models.Decision
        Stream             *stream.EventStream

	PluginChannel chan csplugin.ProfileAlert
	ConsoleConfig csconfig.ConsoleConfig
	TrustedIPs    []net.IPNet
}

type ControllerV1Config struct {
	DbClient    *database.Client
	Ctx         context.Context
	ProfilesCfg []*csconfig.ProfileCfg

	AlertsAddChan      chan []*models.Alert
	DecisionDeleteChan chan []*models.Decision
        Stream             *stream.EventStream

	PluginChannel chan csplugin.ProfileAlert
	ConsoleConfig csconfig.ConsoleConfig
	TrustedIPs    []net.IPNet
}

func New(cfg *ControllerV1Config) (*Controller, error) {
	var err error

	profiles, err := csprofiles.NewProfile(cfg.ProfilesCfg)
	if err != nil {
		return &Controller{}, fmt.Errorf("failed to compile profiles: %w", err)
	}

	v1 := &Controller{
		Ectx:               cfg.Ctx,
		DBClient:           cfg.DbClient,
		APIKeyHeader:       middlewares.APIKeyHeader,
		Profiles:           profiles,
		AlertsAddChan:      cfg.AlertsAddChan,
		DecisionDeleteChan: cfg.DecisionDeleteChan,
                Stream:             cfg.Stream,
		PluginChannel:      cfg.PluginChannel,
		ConsoleConfig:      cfg.ConsoleConfig,
		TrustedIPs:         cfg.TrustedIPs,
	}
	v1.Middlewares, err = middlewares.NewMiddlewares(cfg.DbClient)
	if err != nil {
		return v1, err
	}
	return v1, nil
}
