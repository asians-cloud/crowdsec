package v1

import (
	"net/http"

	"github.com/asians-cloud/crowdsec/pkg/models"
	"github.com/asians-cloud/crowdsec/pkg/types"
	"github.com/gin-gonic/gin"
	"github.com/go-openapi/strfmt"
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
	machineID := gctx.Query("machine_id")
	password := gctx.Query("password")
	
	if machineID == "" {
		var input struct {
			MachineID *string `json:"machine_id"`
			Password  *string `json:"password"`
		}
		if err := gctx.ShouldBindJSON(&input); err == nil {
			if input.MachineID != nil {
				machineID = *input.MachineID
			}
			if input.Password != nil {
				password = *input.Password
			}
		}
	}
	
	if machineID == "" {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": "machine_id is required"})
		return
	}
	
	if password == "" {
		gctx.JSON(http.StatusBadRequest, gin.H{"message": "password is required"})
		return
	}

	machine, err := c.DBClient.QueryMachineByID(machineID)
	if err != nil {
		gctx.JSON(http.StatusUnauthorized, gin.H{"message": "machine not found"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(machine.Password), []byte(password)); err != nil {
		gctx.JSON(http.StatusUnauthorized, gin.H{"message": "invalid password"})
		return
	}

	if machine.IsValidated {
		gctx.JSON(http.StatusOK, gin.H{
			"message": "machine is already validated",
			"machine_id": machineID,
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
		"message": "machine has been validated successfully",
		"machine_id": machineID,
		"is_validated": true,
	})
}
