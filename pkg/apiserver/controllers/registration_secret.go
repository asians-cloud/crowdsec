package controllers

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const RegistrationSecretHeader = "X-Crowdsec-Registration-Secret"

func RegistrationSecretMiddleware(expected string) gin.HandlerFunc {
	want := strings.TrimSpace(expected)
	wantBytes := []byte(want)
	return func(c *gin.Context) {
		if len(wantBytes) == 0 {
			c.JSON(http.StatusForbidden, gin.H{
				"message": "remote registration is disabled: set a non-empty api.server.registration_secret and send it in header " + RegistrationSecretHeader,
			})
			c.Abort()
			return
		}
		got := strings.TrimSpace(c.GetHeader(RegistrationSecretHeader))
		if subtle.ConstantTimeCompare(wantBytes, []byte(got)) != 1 {
			c.JSON(http.StatusForbidden, gin.H{"message": "invalid registration secret"})
			c.Abort()
			return
		}
		c.Next()
	}
}
