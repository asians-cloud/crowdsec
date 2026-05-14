package v1

import (
	"fmt"
	"net/http"

	middlewares "github.com/asians-cloud/crowdsec/pkg/apiserver/middlewares/v1"
	"github.com/asians-cloud/crowdsec/pkg/types"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type AddBouncerRequest struct {
	MachineID   *string `json:"machine_id" binding:"required"`
	Password    *string `json:"password" binding:"required"`
	BouncerName *string `json:"bouncer_name" binding:"required"`
	BouncerKey  *string `json:"bouncer_key" binding:"required"`
}

func (r AddBouncerRequest) Validate() error {
	if r.MachineID == nil || *r.MachineID == "" {
		return fmt.Errorf("machine_id is required")
	}
	if r.Password == nil || *r.Password == "" {
		return fmt.Errorf("password is required")
	}
	if r.BouncerName == nil || *r.BouncerName == "" {
		return fmt.Errorf("bouncer_name is required")
	}
	if r.BouncerKey == nil || *r.BouncerKey == "" {
		return fmt.Errorf("bouncer_key is required")
	}
	return nil
}

func (c *Controller) AddBouncer(gctx *gin.Context) {
	var input AddBouncerRequest

	if err := gctx.ShouldBindJSON(&input); err != nil {
		log.Errorf("AddBouncer: invalid request body: %s", err)
		gctx.JSON(http.StatusBadRequest, gin.H{"message": "invalid request body"})
		return
	}

	if err := input.Validate(); err != nil {
		log.Errorf("AddBouncer: validation failed: %s", err)
		gctx.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	machineID := *input.MachineID
	password := *input.Password

	machine, err := c.DBClient.QueryMachineByID(machineID)

	if err != nil {
		log.Errorf("AddBouncer: machine '%s' not found: %s", machineID, err)
		gctx.JSON(http.StatusUnauthorized, gin.H{"message": "authentication failed"})
		return
	}

	if machine == nil {
		log.Errorf("AddBouncer: machine '%s' not found", machineID)
		gctx.JSON(http.StatusUnauthorized, gin.H{"message": "authentication failed"})
		return
	}

	if !machine.IsValidated {
		log.Errorf("AddBouncer: machine '%s' is not validated", machineID)
		gctx.JSON(http.StatusUnauthorized, gin.H{"message": "machine not validated"})
		return
	}

	if machine.AuthType != types.PasswordAuthType {
		log.Errorf("AddBouncer: machine '%s' attempted to auth with password but is configured to use %s", machineID, machine.AuthType)
		gctx.JSON(http.StatusUnauthorized, gin.H{"message": "authentication failed"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(machine.Password), []byte(password)); err != nil {
		log.Errorf("AddBouncer: invalid password for machine '%s'", machineID)
		gctx.JSON(http.StatusUnauthorized, gin.H{"message": "authentication failed"})
		return
	}

	bouncerName := *input.BouncerName
	bouncerKey := *input.BouncerKey

	hashedKey := middlewares.HashSHA512(bouncerKey)

	bouncer, err := c.DBClient.CreateBouncer(bouncerName, gctx.ClientIP(), hashedKey, types.ApiKeyAuthType)
	if err != nil {
		log.Errorf("AddBouncer: failed to create bouncer '%s': %s", bouncerName, err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": "failed to create bouncer"})
		return
	}

	log.Infof("AddBouncer: machine '%s' successfully created bouncer '%s'", machineID, bouncerName)

	gctx.JSON(http.StatusCreated, gin.H{
		"message":      "bouncer created successfully",
		"bouncer_name": bouncer.Name,
	})
}

type deleteBouncerRequest struct {
	MachineID   *string `json:"machine_id" binding:"required"`
	Password    *string `json:"password" binding:"required"`
	BouncerName *string `json:"bouncer_name" binding:"required"`
}

func (c *Controller) DeleteBouncer(gctx *gin.Context) {
	var input deleteBouncerRequest
	if err := gctx.ShouldBindJSON(&input); err != nil {
		log.Errorf("DeleteBouncer: invalid request body: %s", err)
		gctx.JSON(http.StatusBadRequest, gin.H{"message": "invalid request body"})
		return
	}
	if *input.MachineID == "" || *input.Password == "" || *input.BouncerName == "" {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": "machine_id, password, and bouncer_name are required"})
		return
	}

	machineID := *input.MachineID
	password := *input.Password
	bouncerName := *input.BouncerName

	machine, err := c.DBClient.QueryMachineByID(machineID)
	if err != nil {
		log.Errorf("DeleteBouncer: machine '%s': %s", machineID, err)
		gctx.JSON(http.StatusUnauthorized, gin.H{"message": "authentication failed"})
		return
	}
	if machine.AuthType != types.PasswordAuthType {
		log.Errorf("DeleteBouncer: machine '%s' wrong auth type", machineID)
		gctx.JSON(http.StatusUnauthorized, gin.H{"message": "authentication failed"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(machine.Password), []byte(password)); err != nil {
		log.Errorf("DeleteBouncer: invalid password for machine '%s'", machineID)
		gctx.JSON(http.StatusUnauthorized, gin.H{"message": "authentication failed"})
		return
	}

	if err := c.DBClient.DeleteBouncerAllowMissing(bouncerName); err != nil {
		log.Errorf("DeleteBouncer: failed to delete '%s': %s", bouncerName, err)
		gctx.JSON(http.StatusInternalServerError, gin.H{"message": "failed to delete bouncer"})
		return
	}

	gctx.JSON(http.StatusOK, gin.H{"message": "bouncer deleted", "bouncer_name": bouncerName})
}
