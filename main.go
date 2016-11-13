package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

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
		// TODO: enable once we have some sort of throttling in place!
		/*for _, m := range mxs {
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
					r.Errors = append(r.Errors, e)
				}
			case <-time.After(2 * time.Second):
				r.Errors = append(r.Errors, fmt.Sprintf("timeout establishing TLS connection to %v", m.Host))
				continue
			}
		}*/

		c.JSON(200, r)
	})

	router.Run(":" + port)
}
