package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	sonargo "github.com/deletescape/sonargo/sonar"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
)

var (
	noDl       bool
	shodanFile string
)

func init() {
	flag.BoolVar(&noDl, "n", false, "Doesn't download discovered projects, and only prints info about them")
	flag.StringVar(&shodanFile, "s", "", "Path to a Shodan download file with hosts to run against")
}

func main() {
	flag.Parse()

	if shodanFile == "" && flag.Arg(0) == "" {
		fmt.Println("usage:", os.Args[0], "<options> [endpoint]")
		fmt.Println("    example:", os.Args[0], "-n https://sonar.example.com/api")
		os.Exit(1)
	}

	if shodanFile == "" {
		err := checkServer(flag.Arg(0))
		if err != nil {
			log.Fatal(err)
		}
	} else {
		info, err := os.Stat(shodanFile)
		if os.IsNotExist(err) || info.IsDir() {
			log.Fatalln("error: file", shodanFile, "is not a file or doesn't exist")
		}

		file, err := os.Open(shodanFile)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		scanner.Buffer(nil, 500000)
		for scanner.Scan() {
			var record ShodanRecord
			if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
				os.Stderr.WriteString(fmt.Sprintln("error:", err))
				continue
			}
			baseUrl := &url.URL{
				Scheme: record.Scheme(),
				Host:   record.Host(),
				Path:   "/api",
			}
			if noDl {
				fmt.Printf("baseUrl %s\n", baseUrl)
				record.Print()
				fmt.Println("projects:")
			}
			if err := checkServer(baseUrl.String()); err != nil {
				fmt.Println("---")
				fmt.Println()
				os.Stderr.WriteString(fmt.Sprintln("error:", err))
				continue
			}
			fmt.Println("---")
			fmt.Println()
		}

		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
	}
}

func checkServer(url string) error {
	client, err := sonargo.NewAnonymousClient(url)
	if err != nil {
		return err
	}

	v, _, err := client.Projects.Search(&sonargo.ProjectsSearchOption{
		Ps: "500",
	})
	if err != nil {
		return err
	}
	for _, c := range v.Components {
		if noDl {
			fmt.Printf("    %s (%s)\n", c.Name, c.Key)
		} else {
			fmt.Println("Downloading", c.Key)
			os.Mkdir(c.Key, os.ModePerm)
			tree, _, err := client.Components.Tree(&sonargo.ComponentsTreeOption{
				Component: c.Key,
				Ps:        "500",
				S:         "qualifier,name",
				Strategy:  "children",
			})
			if err != nil {
				fmt.Printf("error: %v\n", err)
				continue
			}
			baseDir, _ := filepath.Abs(c.Key)
			recurseTree(baseDir, client, tree.Components)
		}
	}
	return nil
}

func recurseTree(dir string, client *sonargo.Client, components []*sonargo.Component) {
	for _, c := range components {
		switch c.Qualifier {
		case "DIR", "BRC":
			p := path.Join(dir, c.Path)
			os.MkdirAll(p, os.ModePerm)
			tree, _, err := client.Components.Tree(&sonargo.ComponentsTreeOption{
				Component: c.Key,
				Ps:        "500",
				S:         "qualifier,name",
				Strategy:  "children",
			})
			if err != nil {
				fmt.Printf("error: %v\n", err)
				continue
			}
			recurseTree(p, client, tree.Components)
		case "FIL", "UTS":
			raw, _, err := client.Sources.Raw(&sonargo.SourcesRawOption{
				Key: c.Key,
			})
			if err != nil {
				fmt.Printf("error: %v\n", err)
				continue
			}
			p := path.Join(dir, c.Name)
			f, err := os.Create(p)
			if err != nil {
				fmt.Println("dir:", dir)
				fmt.Printf("error: %v\n", err)
				continue
			}
			f.WriteString(*raw)
			f.Close()
		default:
			fmt.Printf("Unknown qualifier %s\n", c.Qualifier)
		}
	}
}
