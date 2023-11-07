package controllers

import (
  "sync"
  "github.com/asians-cloud/crowdsec/pkg/stream"
  "github.com/gin-gonic/gin"
  log "github.com/sirupsen/logrus"
)

// It Listens all incoming requests from clients.
// Handles addition and removal of clients and broadcast messages to clients.
func listen(s *stream.EventStream) {
  var mu sync.Mutex
  for {
    select {
    // Add new available client
    case client := <-s.NewClients:
      s.TotalClients[client] = true 

    // Remove closed client
    case client := <-s.ClosedClients:
      mu.Lock()
      delete(s.TotalClients, client)
      close(client)
      mu.Unlock()

    // Broadcast message to client
    case eventMsg := <-s.Message:
      log.Printf("Broadcast to %d registered clients", len(s.TotalClients))
      for clientMessageChan := range s.TotalClients {
        clientMessageChan := clientMessageChan
        go func() {
          mu.Lock()
          clientMessageChan <- eventMsg
          mu.Unlock()
        }()
      }
    }
  }
}

func serveHTTP(s *stream.EventStream) gin.HandlerFunc {
  return func(c *gin.Context) {
    // Initialize client channel
    clientChan := make(stream.ClientChan)

    // Send new connection to event server
    s.NewClients <- clientChan

    defer func() {
      // Send closed connection to event server
      s.ClosedClients <- clientChan
    }()

    go func() {
      <-c.Done()
      s.ClosedClients <- clientChan
    }()

    c.Set("clientChan", clientChan)

    c.Next()
  }
}

func NewServer() (event *stream.EventStream) {
  event = &stream.EventStream{
    Message:       make(chan string),
    NewClients:    make(chan chan string),
    ClosedClients: make(chan chan string),
    TotalClients:  make(map[chan string]bool),
  }

  go listen(event)

  return
}