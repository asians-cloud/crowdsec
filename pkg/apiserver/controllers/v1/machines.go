package v1

import (
	"errors"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"github.com/crowdsecurity/crowdsec/pkg/database"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/crowdsec/pkg/types"
)

func (c *Controller) shouldAutoRegister(token string, gctx *gin.Context) (bool, error) {
	if c.AutoRegisterCfg == nil || c.AutoRegisterCfg.Enable == nil || !*c.AutoRegisterCfg.Enable {
		return false, nil
	}

	clientIP := net.ParseIP(gctx.ClientIP())

	// Can probaby happen if using unix socket ?
	if clientIP == nil {
		log.Warnf("Failed to parse client IP for watcher self registration: %s", gctx.ClientIP())
		return false, nil
	}

	if token == "" {
		return false, nil
	}

	// Check the token
	if token != c.AutoRegisterCfg.Token {
		return false, errors.New("invalid token for auto registration")
	}

	// Check the source IP
	for _, ipRange := range c.AutoRegisterCfg.AllowedRangesParsed {
		if ipRange.Contains(clientIP) {
			return true, nil
		}
	}

	return false, errors.New("IP not in allowed range for auto registration")
}

func (c *Controller) CreateMachine(gctx *gin.Context) {
	ctx := gctx.Request.Context()

	var input models.WatcherRegistrationRequest

	if err := gctx.ShouldBindJSON(&input); err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	if err := input.Validate(strfmt.Default); err != nil {
		gctx.JSON(http.StatusUnprocessableEntity, gin.H{"message": err.Error()})
		return
	}

	autoRegister, err := c.shouldAutoRegister(input.RegistrationToken, gctx)
	if err != nil {
		log.WithFields(log.Fields{"ip": gctx.ClientIP(), "machine_id": *input.MachineID}).Errorf("Auto-register failed: %s", err)
		gctx.JSON(http.StatusUnauthorized, gin.H{"message": err.Error()})

		return
	}

	if _, err := c.DBClient.CreateMachine(ctx, input.MachineID, input.Password, gctx.ClientIP(), autoRegister, false, types.PasswordAuthType); err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	if autoRegister {
		log.WithFields(log.Fields{"ip": gctx.ClientIP(), "machine_id": *input.MachineID}).Info("Auto-registered machine")
		gctx.Status(http.StatusAccepted)
	} else {
		gctx.Status(http.StatusCreated)
	}
}

func (c *Controller) DeleteMachine(gctx *gin.Context) {
	ctx := gctx.Request.Context()

	machineID, err := getMachineIDFromContext(gctx)

	if err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	if machineID == "" {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": "machineID not found in claims"})
		return
	}

	if err := c.DBClient.DeleteWatcher(ctx, machineID); err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	log.WithFields(log.Fields{"ip": gctx.ClientIP(), "machine_id": machineID}).Info("Deleted machine")

	gctx.Status(http.StatusNoContent)
}

func (c *Controller) ValidateMachine(gctx *gin.Context) {
	ctx := gctx.Request.Context()

	var input struct {
		MachineID *string `json:"machine_id" binding:"required"`
		Password  *string `json:"password" binding:"required"`
	}

	if err := gctx.ShouldBindJSON(&input); err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": "invalid request body"})

		return
	}

	machineID := *input.MachineID
	password := *input.Password

	machine, err := c.DBClient.QueryMachineByID(ctx, machineID)
	if err != nil {
		gctx.JSON(http.StatusUnauthorized, gin.H{"message": "machine not found"})

		return
	}

	if machine.AuthType != types.PasswordAuthType {
		gctx.JSON(http.StatusUnauthorized, gin.H{"message": "authentication failed"})

		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(machine.Password), []byte(password)); err != nil {
		gctx.JSON(http.StatusUnauthorized, gin.H{"message": "invalid password"})

		return
	}

	if machine.IsValidated {
		gctx.JSON(http.StatusOK, gin.H{
			"message":      "machine is already validated",
			"machine_id":   machineID,
			"is_validated": true,
		})

		return
	}

	if err := c.DBClient.ValidateMachine(ctx, machineID); err != nil {
		c.HandleDBErrors(gctx, err)

		return
	}

	gctx.JSON(http.StatusOK, gin.H{
		"message":      "machine has been validated successfully",
		"machine_id":   machineID,
		"is_validated": true,
	})
}

type unregisterMachineRequest struct {
	MachineID *string `json:"machine_id" binding:"required"`
	Password  *string `json:"password" binding:"required"`
}

// UnregisterMachine deletes a machine using machine_id + password credentials.
// Used by POST /v1/watchers/delete (remote registration flow).
func (c *Controller) UnregisterMachine(gctx *gin.Context) {
	ctx := gctx.Request.Context()

	var input unregisterMachineRequest
	if err := gctx.ShouldBindJSON(&input); err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": "invalid request body"})

		return
	}

	machineID := *input.MachineID
	password := *input.Password

	machine, err := c.DBClient.QueryMachineByID(ctx, machineID)
	if err != nil {
		if errors.Is(err, database.UserNotExists) {
			gctx.JSON(http.StatusOK, gin.H{"message": "machine not registered"})

			return
		}

		c.HandleDBErrors(gctx, err)

		return
	}

	if machine.AuthType != types.PasswordAuthType {
		gctx.JSON(http.StatusUnauthorized, gin.H{"message": "authentication failed"})

		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(machine.Password), []byte(password)); err != nil {
		gctx.JSON(http.StatusUnauthorized, gin.H{"message": "authentication failed"})

		return
	}

	if err := c.DBClient.DeleteWatcher(ctx, machineID); err != nil {
		var notFound *database.MachineNotFoundError
		if errors.As(err, &notFound) {
			gctx.JSON(http.StatusOK, gin.H{"message": "machine not registered"})

			return
		}

		c.HandleDBErrors(gctx, err)

		return
	}

	gctx.JSON(http.StatusOK, gin.H{"message": "machine deleted"})
}
