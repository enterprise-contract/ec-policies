// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/enterprise-contract/ec-policies/docs/asciidoc"
)

var adoc = flag.String("adoc", "", "Location of the generated Asciidoc files")

var rego stringAry

type stringAry []string

func (s *stringAry) String() string {
	return strings.Join(*s, ",")
}

func (s *stringAry) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	flag.Var(&rego, "rego", "Location of the Rego files")
	flag.Parse()

	if *adoc == "" || len(rego) == 0 {
		fmt.Fprintf(os.Stderr, "-adoc and -rego flags are required\n")
		os.Exit(1)
	}

	var err error
	defer func() {
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
	}()

	if err = os.MkdirAll(*adoc, 0755); err != nil {
		return
	}

	if err = asciidoc.GenerateAsciidoc(*adoc, rego...); err != nil {
		return
	}
}
