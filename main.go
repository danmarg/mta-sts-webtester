package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"

	"github.com/danmarg/smtp-sts"
)

func main() {
	port := os.Getenv("PORT")

	if port == "" {
		log.Fatal("$PORT must be set")
	}

	router := gin.New()
	router.Use(gin.Logger())
	router.LoadHTMLGlob("templates/*.tmpl.html")
	router.Static("/static", "static")

	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.tmpl.html", nil)
	})

	chc := cache.New(5*time.Minute, 30*time.Second)

	router.GET("/test/:domain", func(c *gin.Context) {
		var e error
		d := c.Param("domain")
		r := struct {
			Errors        []string `json:"errors"`
			PolicyId      string   `json:"policy_id"`
			PolicyMXs     []string `json:"policy_mxs"`
			PolicyMode    string   `json:"policy_mode"`
			PolicyExpires string   `json:"policy_expires"`
			MXs           []string `json:"mxs"`
		}{}
		r.PolicyId, e = sts.PolicyVersionForDomain(d)
		if e != nil {
			r.Errors = append(r.Errors, fmt.Sprintf("error fetching policy marker via DNS: %v", e))
			// This is continuable, at least.
		}
		p, e := sts.PolicyForDomain(d)
		if e != nil {
			r.Errors = append(r.Errors, fmt.Sprintf("error fetching policy via HTTPS: %v", e))
			// Un-continuable.
			c.JSON(200, r)
			return
		}
		r.PolicyMXs = p.MXs
		if p.Mode == sts.Policy_REPORT {
			r.PolicyMode = "report"
		} else {
			r.PolicyMode = "enforce"
		}
		r.PolicyExpires = p.Expires.String()
		mxs, e := net.LookupMX(d)
		if e != nil || len(mxs) == 0 {
			r.Errors = append(r.Errors, fmt.Sprintf("error fetching MXs via DNS: %v", e))
			// Un-continuable.
			c.JSON(200, r)
			return
		}
		mxs, e = sts.FilterMXs(mxs, p)
		if e != nil {
			r.Errors = append(r.Errors, fmt.Sprintf("error filtering valid MXs: %v", e))
		}
		for _, m := range mxs {
			r.MXs = append(r.MXs, m.Host)
		}
		// Check the TLS connections themselves, with a timeout.
		var mxerrs []string
		m, ok := chc.Get(d)
		if !ok {
			for _, m := range mxs {
				c := make(chan string, 1)
				go func(c chan<- string) {
					if e := sts.CheckMXViaSMTP(m); e != nil {
						c <- fmt.Sprintf("error establishing TLS connection to %v: %v", m.Host, e)
					} else {
						c <- ""
					}
				}(c)
				select {
				case e := <-c:
					if e != "" {
						mxerrs = append(mxerrs, e)
					}
				case <-time.After(2 * time.Second):
					mxerrs = append(mxerrs, fmt.Sprintf("timeout establishing TLS connection to %v", m.Host))
					continue
				}
			}
			chc.Set(d, mxerrs, cache.DefaultExpiration)
		} else {
			mxerrs = m.([]string)
		}
		r.Errors = append(r.Errors, mxerrs...)
		c.JSON(200, r)
	})

	router.Run(":" + port)
}
