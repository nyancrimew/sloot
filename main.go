package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	sonargo "github.com/deletescape/sonargo/sonar"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
)

var (
	quiet      bool
	noDl       bool
	shodanFile string
)

func init() {
	flag.BoolVar(&quiet, "q", false, "Don't print non-fatal errors")
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
		out, err := checkServer(flag.Arg(0), ".")
		if err != nil {
			log.Fatal(err)
		}
		for _, l := range out {
			fmt.Println(l)
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
				if !quiet {
					os.Stderr.WriteString(fmt.Sprintln("error:", err))
				}
				continue
			}
			baseUrl := &url.URL{
				Scheme: record.Scheme(),
				Host:   record.Host(),
				Path:   "/api",
			}
			os.Mkdir(record.Host(), os.ModePerm)
			hostDir, _ := filepath.Abs(record.Host())
			ioutil.WriteFile(filepath.Join(hostDir, "shodan.json"), scanner.Bytes(), os.ModePerm)
			out, err := checkServer(baseUrl.String(), hostDir)
			if err != nil {
				if !quiet {
					os.Stderr.WriteString(fmt.Sprintln("error:", err))
				}
				continue
			}
			if noDl {
				fmt.Println()
				record.Print()
				fmt.Println("projects:")
				for _, l := range out {
					fmt.Println(l)
				}
				fmt.Println()
			}
		}

		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
	}
}

func checkServer(url string, base string) ([]string, error) {
	var out []string

	client, err := sonargo.NewAnonymousClient(url)
	if err != nil {
		return out, err
	}

	v, _, err := client.Projects.Search(&sonargo.ProjectsSearchOption{
		Ps: "500",
	})
	if err != nil {
		return out, err
	}
	comps := v.Components
	for v.Paging.PageIndex < v.Paging.Total {
		v, _, err = client.Projects.Search(&sonargo.ProjectsSearchOption{
			Ps: "500",
			P:  fmt.Sprint(v.Paging.PageIndex + 1),
		})
		if err != nil {
			os.Stderr.WriteString(fmt.Sprintln("error:", err))
			break
		}
		comps = append(comps, v.Components...)
	}
	for _, c := range comps {
		if noDl {
			if c.Key == c.Name {
				out = append(out, fmt.Sprintf("    %s", c.Key))
			} else {
				out = append(out, fmt.Sprintf("    %s (%s)", c.Name, c.Key))
			}
		} else {
			fmt.Println("Downloading", c.Key)
			os.Mkdir(filepath.Join(base, c.Key), os.ModePerm)
			tree, _, err := client.Components.Tree(&sonargo.ComponentsTreeOption{
				Component: c.Key,
				Ps:        "500",
				S:         "qualifier,name",
				Strategy:  "children",
			})
			if err != nil {
				if !quiet {
					os.Stderr.WriteString(fmt.Sprintln("error:", err))
				}
				continue
			}
			comps := tree.Components
			for tree.Paging.PageIndex < tree.Paging.Total {
				tree, _, err = client.Components.Tree(&sonargo.ComponentsTreeOption{
					Component: c.Key,
					P:         fmt.Sprint(tree.Paging.PageIndex + 1),
					Ps:        "500",
					S:         "qualifier,name",
					Strategy:  "children",
				})
				if err != nil {
					if !quiet {
						os.Stderr.WriteString(fmt.Sprintln("error:", err))
					}
					break
				}
				comps = append(comps, tree.Components...)
			}
			baseDir, _ := filepath.Abs(filepath.Join(base, c.Key))
			recurseTree(baseDir, client, comps)
		}
	}
	return out, nil
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
				if !quiet {
					os.Stderr.WriteString(fmt.Sprintln("error:", err))
				}
				continue
			}
			comps := tree.Components
			for tree.Paging.PageIndex < tree.Paging.Total {
				tree, _, err = client.Components.Tree(&sonargo.ComponentsTreeOption{
					Component: c.Key,
					P:         fmt.Sprint(tree.Paging.PageIndex + 1),
					Ps:        "500",
					S:         "qualifier,name",
					Strategy:  "children",
				})
				if err != nil {
					if !quiet {
						os.Stderr.WriteString(fmt.Sprintln("error:", err))
					}
					break
				}
				comps = append(comps, tree.Components...)
			}
			recurseTree(p, client, comps)
		case "FIL", "UTS":
			go func(dir string, c sonargo.Component) {
				raw, _, err := client.Sources.Raw(&sonargo.SourcesRawOption{
					Key: c.Key,
				})
				if err != nil {
					if !quiet {
						os.Stderr.WriteString(fmt.Sprintln("error:", err))
					}
					return
				}
				p := path.Join(dir, c.Name)
				f, err := os.Create(p)
				if err != nil {
					if !quiet {
						os.Stderr.WriteString(fmt.Sprintln("error:", err))
					}
					return
				}
				f.WriteString(*raw)
				f.Close()
			}(dir, *c)
		default:
			fmt.Printf("Unknown qualifier %s\n", c.Qualifier)
		}
	}
}
