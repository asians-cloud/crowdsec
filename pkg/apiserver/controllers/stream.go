package controllers

import (
  "github.com/asians-cloud/crowdsec/pkg/stream"
  "github.com/gin-gonic/gin"
  log "github.com/sirupsen/logrus"
)

// It keeps a list of clients those are currently attached
// and broadcasting events to those clients.
type EventStream struct {
  // Events are pushed to this channel by the main events-gathering routine
  Message chan string

  // New client connections
  NewClients chan chan string

  // Closed client connections
  ClosedClients chan chan string

  // Total client connections
  TotalClients map[chan string]bool
}

// It Listens all incoming requests from clients.
// Handles addition and removal of clients and broadcast messages to clients.
func (s *EventStream) listen() {
  for {
    select {
    // Add new available client
    case client := <-s.NewClients:
      s.TotalClients[client] = true
      log.Printf("Client added. %d registered clients", len(s.TotalClients))

    // Remove closed client
    case client := <-s.ClosedClients:
      delete(s.TotalClients, client)
      close(client)
      log.Printf("Removed client. %d registered clients", len(s.TotalClients))

    // Broadcast message to client
    case eventMsg := <-s.Message:
      for clientMessageChan := range s.TotalClients {
        clientMessageChan <- eventMsg
      }
    }
  }
}

func (s *EventStream) serveHTTP() gin.HandlerFunc {
  return func(c *gin.Context) {
    // Initialize client channel
    clientChan := make(stream.ClientChan)

    // Send new connection to event server
    s.NewClients <- clientChan

    defer func() {
            // Send closed connection to event server
            s.ClosedClients <- clientChan
    }()

    c.Set("clientChan", clientChan)

    c.Next()
  }
}

func NewServer() (event *EventStream) {
  event = &EventStream{
    Message:       make(chan string),
    NewClients:    make(chan chan string),
    ClosedClients: make(chan chan string),
    TotalClients:  make(map[chan string]bool),
  }

  go event.listen()

  return
}
