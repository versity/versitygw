// Copyright 2023 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package integration

import "fmt"

var (
	colorReset = "\033[0m"
	colorRed   = "\033[31m"
	colorGreen = "\033[32m"
	colorCyan  = "\033[36m"
)

var (
	RunCount  = 0
	PassCount = 0
	FailCount = 0
)

func runF(format string, a ...interface{}) {
	RunCount++
	fmt.Printf(colorCyan+"RUN  "+colorReset+format+"\n", a...)
}

func failF(format string, a ...interface{}) {
	FailCount++
	fmt.Printf(colorRed+"FAIL "+colorReset+format+"\n", a...)
}

func passF(format string, a ...interface{}) {
	PassCount++
	fmt.Printf(colorGreen+"PASS "+colorReset+format+"\n", a...)
}
