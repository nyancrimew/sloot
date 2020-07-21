package main

import "fmt"

type ShodanRecord struct {
	Shodan struct {
		ID      string `json:"id"`
		Options struct {
		} `json:"options"`
		Ptr     bool   `json:"ptr"`
		Module  string `json:"module"`
		Crawler string `json:"crawler"`
	} `json:"_shodan"`
	Product string      `json:"product"`
	Hash    int         `json:"hash"`
	Os      interface{} `json:"os"`
	Opts    struct {
		Vulns      []interface{} `json:"vulns"`
		Heartbleed string        `json:"heartbleed"`
	} `json:"opts"`
	IP   int64  `json:"ip"`
	Isp  string `json:"isp"`
	HTTP struct {
		HTMLHash   int `json:"html_hash"`
		RobotsHash int `json:"robots_hash"`
		Redirects  []struct {
			Host     string `json:"host"`
			Data     string `json:"data"`
			Location string `json:"location"`
		} `json:"redirects"`
		Securitytxt interface{} `json:"securitytxt"`
		Title       string      `json:"title"`
		SitemapHash interface{} `json:"sitemap_hash"`
		Robots      string      `json:"robots"`
		Favicon     struct {
			Hash     int    `json:"hash"`
			Data     string `json:"data"`
			Location string `json:"location"`
		} `json:"favicon"`
		Host       string `json:"host"`
		HTML       string `json:"html"`
		Location   string `json:"location"`
		Components struct {
			GitLab struct {
				Categories []interface{} `json:"categories"`
			} `json:"GitLab"`
			Ruby struct {
				Categories []interface{} `json:"categories"`
			} `json:"Ruby"`
			RubyOnRails struct {
				Categories []interface{} `json:"categories"`
			} `json:"Ruby on Rails"`
			VueJs struct {
				Categories []interface{} `json:"categories"`
			} `json:"Vue.js"`
		} `json:"components"`
		Server          string      `json:"server"`
		Sitemap         interface{} `json:"sitemap"`
		SecuritytxtHash interface{} `json:"securitytxt_hash"`
	} `json:"http"`
	Cpe  []string `json:"cpe"`
	Port int      `json:"port"`
	Ssl  struct {
		Dhparams interface{} `json:"dhparams"`
		Tlsext   []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"tlsext"`
		Versions      []string      `json:"versions"`
		AcceptableCas []interface{} `json:"acceptable_cas"`
		Cert          struct {
			SigAlg     string `json:"sig_alg"`
			Issued     string `json:"issued"`
			Expires    string `json:"expires"`
			Expired    bool   `json:"expired"`
			Version    int    `json:"version"`
			Extensions []struct {
				Critical bool   `json:"critical,omitempty"`
				Data     string `json:"data"`
				Name     string `json:"name"`
			} `json:"extensions"`
			Fingerprint struct {
				Sha256 string `json:"sha256"`
				Sha1   string `json:"sha1"`
			} `json:"fingerprint"`
			Serial  interface{} `json:"serial"`
			Subject struct {
				CN string `json:"CN"`
			} `json:"subject"`
			Pubkey struct {
				Type string `json:"type"`
				Bits int    `json:"bits"`
			} `json:"pubkey"`
			Issuer struct {
				C  string `json:"C"`
				CN string `json:"CN"`
				O  string `json:"O"`
			} `json:"issuer"`
		} `json:"cert"`
		Cipher struct {
			Version string `json:"version"`
			Bits    int    `json:"bits"`
			Name    string `json:"name"`
		} `json:"cipher"`
		Chain []string `json:"chain"`
		Alpn  []string `json:"alpn"`
	} `json:"ssl"`
	Hostnames []string `json:"hostnames"`
	Location  struct {
		City         interface{} `json:"city"`
		RegionCode   interface{} `json:"region_code"`
		AreaCode     interface{} `json:"area_code"`
		Longitude    float64     `json:"longitude"`
		CountryCode3 interface{} `json:"country_code3"`
		CountryName  string      `json:"country_name"`
		PostalCode   interface{} `json:"postal_code"`
		DmaCode      interface{} `json:"dma_code"`
		CountryCode  string      `json:"country_code"`
		Latitude     float64     `json:"latitude"`
	} `json:"location"`
	Timestamp string   `json:"timestamp"`
	Domains   []string `json:"domains"`
	Org       string   `json:"org"`
	Data      string   `json:"data"`
	Asn       string   `json:"asn"`
	Transport string   `json:"transport"`
	IPStr     string   `json:"ip_str"`
}

func (r *ShodanRecord) Scheme() string {
	if r.Shodan.Module == "https" {
		return "https"
	}
	return "http"
}

func (r *ShodanRecord) Host() string {
	return fmt.Sprintf("%s:%d", r.HTTP.Host, r.Port)
}

func (r *ShodanRecord) Print() {
	fmt.Printf("host: %s\n", r.HTTP.Host)
	fmt.Printf("port: %d\n", r.Port)
	fmt.Printf("scheme: %s\n", r.Scheme())
	fmt.Printf("org: %s (%s)\n", r.Org, r.Asn)
	if r.Shodan.Crawler == "https" {
		fmt.Printf("ssl.cert.subject.cn: %s\n", r.Ssl.Cert.Subject.CN)
		for _, e := range r.Ssl.Cert.Extensions {
			if e.Name == "subjectAltName" {
				fmt.Printf("ssl.cert.extensions[subjectAltName]: %s\n", e.Data)
			}
		}
	}
	if len(r.Hostnames) > 0 {
		fmt.Printf("hostnames: \n")
		for _, h := range r.Hostnames {
			fmt.Printf("    %s\n", h)
		}
	}
}
