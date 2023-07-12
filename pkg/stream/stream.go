package stream

import (
  "github.com/gin-gonic/gin"
)

// New event messages are broadcast to all registered client connection channels
type ClientChan chan string

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

func HeadersMiddleware() gin.HandlerFunc {
  return func(c *gin.Context) {
    c.Writer.Header().Set("Content-Type", "text/event-stream")
    c.Writer.Header().Set("Cache-Control", "no-cache")
    c.Writer.Header().Set("Connection", "keep-alive")
    c.Writer.Header().Set("Transfer-Encoding", "chunked")
    c.Next()
  }
}
