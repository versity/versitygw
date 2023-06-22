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
