package v1

import (
	"net/http"

	"github.com/asians-cloud/crowdsec/pkg/database"
	"github.com/asians-cloud/crowdsec/pkg/models"
	"github.com/asians-cloud/crowdsec/pkg/types"
	"github.com/gin-gonic/gin"
	"github.com/go-openapi/strfmt"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

func (c *Controller) CreateMachine(gctx *gin.Context) {
	var err error
	var input models.WatcherRegistrationRequest
	if err = gctx.ShouldBindJSON(&input); err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}
	if err = input.Validate(strfmt.Default); err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	_, err = c.DBClient.CreateMachine(input.MachineID, input.Password, gctx.ClientIP(), false, false, types.PasswordAuthType)
	if err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	gctx.Status(http.StatusCreated)
}

func (c *Controller) ValidateMachine(gctx *gin.Context) {
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

	machine, err := c.DBClient.QueryMachineByID(machineID)
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

	err = c.DBClient.ValidateMachine(machineID)
	if err != nil {
		c.HandleDBErrors(gctx, err)
		return
	}

	gctx.JSON(http.StatusOK, gin.H{
		"message":      "machine has been validated successfully",
		"machine_id":   machineID,
		"is_validated": true,
	})
}

type deleteMachineRequest struct {
	MachineID *string `json:"machine_id" binding:"required"`
	Password  *string `json:"password" binding:"required"`
}

func (c *Controller) DeleteMachine(gctx *gin.Context) {
	var input deleteMachineRequest
	if err := gctx.ShouldBindJSON(&input); err != nil {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": "invalid request body"})
		return
	}
	machineID := *input.MachineID
	password := *input.Password

	machine, err := c.DBClient.QueryMachineByID(machineID)
	if err != nil {
		if errors.Cause(err) == database.UserNotExists {
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

	if err := c.DBClient.DeleteWatcher(machineID); err != nil {
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}

	gctx.JSON(http.StatusOK, gin.H{"message": "machine deleted"})
}
