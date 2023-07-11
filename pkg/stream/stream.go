package stream

import (
  "github.com/gin-gonic/gin"
)

// New event messages are broadcast to all registered client connection channels
type ClientChan chan string


func HeadersMiddleware() gin.HandlerFunc {
  return func(c *gin.Context) {
    c.Writer.Header().Set("Content-Type", "text/event-stream")
    c.Writer.Header().Set("Cache-Control", "no-cache")
    c.Writer.Header().Set("Connection", "keep-alive")
    c.Writer.Header().Set("Transfer-Encoding", "chunked")
    c.Next()
  }
}
