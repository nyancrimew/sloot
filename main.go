package main

import (
	"fmt"
	sonargo "github.com/deletescape/sonargo/sonar"
	"log"
	"os"
	"path"
	"path/filepath"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("usage:", os.Args[0], "[endpoint]")
		fmt.Println("    example:", os.Args[0], "https://sonar.example.com/api")
		os.Exit(1)
	}
	client, err := sonargo.NewAnonymousClient(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	v, _, err := client.Projects.Search(&sonargo.ProjectsSearchOption{
		Ps: "500",
	})
	if err != nil {
		log.Fatal(err)
	}
	for _, c := range v.Components {
		fmt.Println("Downloading", c.Key)
		os.Mkdir(c.Key, os.ModePerm)
		tree, _, err := client.Components.Tree(&sonargo.ComponentsTreeOption{
			Component:  c.Key,
			Ps:         "500",
			S:          "qualifier,name",
			Strategy:   "children",
		})
		if err != nil {
			fmt.Printf("error: %v\n", err)
			continue
		}
		baseDir, _ := filepath.Abs(c.Key)
		recurseTree(baseDir, client, tree.Components)
	}
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
