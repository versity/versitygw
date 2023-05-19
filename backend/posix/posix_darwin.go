package posix

import (
	"fmt"
	"os"
)

func openTmpFile(dir string) (*os.File, error) {
	return nil, fmt.Errorf("not implemented")
}

func linkTmpFile(f *os.File, path string) error {
	return fmt.Errorf("not implemented")
}
