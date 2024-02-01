// show reads an attestation report and outputs it in a preferred format.
package main

import (
	"flag"
	"os"

	"github.com/google/go-sev-guest/tools/lib/report"
	"github.com/google/logger"
)

var (
	infile = flag.String("in", "-", "Path to attestation file, or - for stdin.")
	inform = flag.String("inform", "in", "Format of the attestation file. "+
		"One of bin, proto, textproto")
	outfile = flag.String("out", "-", "Path to output file, or - for stdout.")
	outform = flag.String("outform", "textproto", "Format of the output file. "+
		"One of bin, proto, textproto, tcb. Tcb is human-readable.")
)

func main() {
	logger.Init("", false, false, os.Stderr)
	flag.Parse()

	attestation, err := report.GetAttestation(*infile, *inform)
	if err != nil {
		logger.Fatal(err)
	}

	bin, err := report.Transform(attestation, *outform)
	if err != nil {
		logger.Fatal(err)
	}

	out := os.Stdout
	if *outfile != "-" {
		out, err = os.OpenFile(*outfile, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			logger.Fatalf("Could not open %q: %v", *outfile, err)
		}
	}

	if _, err := out.Write(bin); err != nil {
		logger.Fatalf("Could not write attestation to %q: %v", *outfile, err)
	}
}
