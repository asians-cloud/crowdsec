package csplugin

import (
	"html"
	"os"
	"text/template"

	"github.com/asians-cloud/crowdsec/pkg/exprhelpers"
	"github.com/asians-cloud/crowdsec/pkg/models"
	log "github.com/sirupsen/logrus"
)

var helpers = template.FuncMap{
	"GetMeta": func(a *models.Alert, metaName string) []string {
		var metaValues []string
		for _, evt := range a.Events {
			for _, meta := range evt.Meta {
				if meta.Key == metaName {
					metaValues = append(metaValues, meta.Value)
				}
			}
		}
		return metaValues
	},
	"CrowdsecCTI": func(x string) any {
		ret, err := exprhelpers.CrowdsecCTI(x)
		if err != nil {
			log.Warningf("error while calling CrowdsecCTI : %s", err)
		}
		return ret
	},
	"Hostname":   os.Hostname,
	"HTMLEscape": html.EscapeString,
}

func funcMap() template.FuncMap {
	return helpers
}
