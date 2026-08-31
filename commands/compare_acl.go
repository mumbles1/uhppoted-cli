package commands

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/template"
	"time"

	"codeberg.org/uhppoted/uhppoted-core/types"
	"codeberg.org/uhppoted/uhppoted-lib/acl"
	"codeberg.org/uhppoted/uhppoted-lib/config"
)

// CompareACLCmd is an initialized CompareACL command for the main() command list
var CompareACLCmd = CompareACL{
	file:    "",
	rptfile: "",
	withPIN: false,
	template: `
-----------------------------------
ACL DIFF REPORT {{ .DateTime }}
{{range $id,$value := .Diffs}}
  DEVICE {{ $id }}{{if or $value.Updated $value.Added $value.Deleted}}{{else}} OK{{end}}{{if $value.Updated}}
    Incorrect:  {{range $value.Updated}}{{. | format}}
                {{end}}{{end}}{{if $value.Added}}
    Missing:    {{range $value.Added}}{{. | format}}
                {{end}}{{end}}{{if $value.Deleted}}
    Unexpected: {{range $value.Deleted}}{{. | format}}
                {{end}}{{end}}{{end}}
-----------------------------------
`,
}

type CompareACL struct {
	file          string
	rptfile       string
	withPIN       bool
	withFirstCard bool
	template      string
}

func (c *CompareACL) Execute(ctx Context) error {
	if ctx.config == nil {
		return fmt.Errorf("compare-acl requires a valid configuration file")
	}

	if err := c.parseArgs(); err != nil {
		return err
	}

	if c.file == "" {
		return fmt.Errorf("please specify the TSV file from which to load the authoritative access control list ")
	}

	tsv, err := os.ReadFile(c.file)
	if err != nil {
		return err
	}

	list, warnings, err := acl.ParseTSV(bytes.NewReader(tsv), ctx.devices, false, c.withPIN, c.withFirstCard)
	if err != nil {
		return err
	}

	for _, w := range warnings {
		fmt.Printf("   ... WARNING    %v\n", w)
	}

	for k, l := range list {
		fmt.Printf("   ... %v  ACL has %v records\n", k, len(l))
	}

	current, errors := acl.GetACL(ctx.uhppote, ctx.devices)
	if len(errors) > 0 {
		return fmt.Errorf("%v", errors)
	}

	compare := func(current acl.ACL, list acl.ACL) (map[uint32]acl.Diff, error) {
		if c.withPIN {
			return acl.CompareWithPIN(current, list)
		} else {
			return acl.Compare(current, list)
		}
	}

	diff, err := compare(current, list)
	if err != nil {
		return err
	}

	widths := map[string]int{}
	for k, v := range diff {
		if w := len(fmt.Sprintf("%v", k)); w > widths["device"] {
			widths["device"] = w
		}

		if w := len(fmt.Sprintf("%v", len(v.Unchanged))); w > widths["unchanged"] {
			widths["unchanged"] = w
		}

		if w := len(fmt.Sprintf("%v", len(v.Updated))); w > widths["updated"] {
			widths["updated"] = w
		}

		if w := len(fmt.Sprintf("%v", len(v.Added))); w > widths["added"] {
			widths["added"] = w
		}

		if w := len(fmt.Sprintf("%v", len(v.Deleted))); w > widths["deleted"] {
			widths["deleted"] = w
		}
	}

	format := fmt.Sprintf("   ... %%-%vv  same:%%-%vv  different:%%-%vv  missing:%%-%vv  extraneous:%%-%vv\n",
		widths["device"],
		widths["unchanged"],
		widths["updated"],
		widths["added"],
		widths["deleted"])

	for k, v := range diff {
		fmt.Printf(format, k, len(v.Unchanged), len(v.Updated), len(v.Added), len(v.Deleted))
	}

	var w bytes.Buffer
	if err := c.report(diff, &w); err != nil {
		return err
	}

	if c.rptfile != "" {
		return os.WriteFile(c.rptfile, w.Bytes(), 0660)
	}

	fmt.Printf("%v\n", w.String())

	return nil
}

func (c *CompareACL) report(diff map[uint32]acl.Diff, w io.Writer) error {
	widths := []int{
		8,  // card number
		10, // from
		10, // to
		1,  // door 1
		1,  // door 2
		1,  // door 3
		1,  // door 4
		0,  // PIN
		0,  // first card
	}

	layout := func(card types.Card) {
		widths[0] = max(widths[0], len(fmt.Sprintf("%-8v", card.CardNumber)))
		widths[1] = max(widths[1], len(fmt.Sprintf("%v", card.From)))
		widths[2] = max(widths[2], len(fmt.Sprintf("%v", card.To)))
		widths[3] = max(widths[3], len(fmt.Sprintf("%v", card.Doors[1])))
		widths[4] = max(widths[4], len(fmt.Sprintf("%v", card.Doors[2])))
		widths[5] = max(widths[5], len(fmt.Sprintf("%v", card.Doors[3])))
		widths[6] = max(widths[6], len(fmt.Sprintf("%v", card.Doors[4])))

		if c.withPIN && card.PIN > 0 && card.PIN < 1000000 {
			widths[7] = max(widths[7], len(fmt.Sprintf("%v", card.PIN)))
		}

		if c.withFirstCard {
			widths[8] = max(widths[8], len(fmt.Sprintf("%v", card.FirstCard)))
		}
	}

	for _, list := range diff {
		for _, card := range list.Unchanged {
			layout(card)
		}

		for _, card := range list.Updated {
			layout(card)
		}

		for _, card := range list.Added {
			layout(card)
		}

		for _, card := range list.Deleted {
			layout(card)
		}
	}

	funcs := template.FuncMap{
		"format": func(v any) string {
			if card, ok := v.(types.Card); ok {
				return c.format(card, widths)
			} else {
				return fmt.Sprintf("%v", v)
			}
		},
	}

	t, err := template.New("report").Funcs(funcs).Parse(c.template)
	if err != nil {
		return err
	}

	timestamp := types.DateTime(time.Now())
	rpt := struct {
		DateTime *types.DateTime
		Diffs    map[uint32]acl.Diff
	}{
		DateTime: &timestamp,
		Diffs:    diff,
	}

	return t.Execute(w, rpt)
}

func (c *CompareACL) format(card types.Card, widths []int) string {
	var b strings.Builder

	f := func(p uint8) string {
		switch {
		case p == 0:
			return "N"

		case p == 1:
			return "Y"

		case p >= 2 && p <= 254:
			return fmt.Sprintf("%v", p)

		default:
			return "N"
		}
	}

	fmt.Fprintf(&b, "%*v", widths[0], card.CardNumber)

	if card.From.IsZero() {
		fmt.Fprintf(&b, " %-*v", widths[1], "-")
	} else {
		fmt.Fprintf(&b, " %-*v", widths[1], card.From)
	}

	if card.To.IsZero() {
		fmt.Fprintf(&b, " %-*v", widths[2], "-")
	} else {
		fmt.Fprintf(&b, " %-*v", widths[2], card.To)
	}

	fmt.Fprintf(&b, " %-*v", widths[3], f(card.Doors[1]))
	fmt.Fprintf(&b, " %-*v", widths[4], f(card.Doors[2]))
	fmt.Fprintf(&b, " %-*v", widths[5], f(card.Doors[3]))
	fmt.Fprintf(&b, " %-*v", widths[6], f(card.Doors[4]))

	if c.withPIN {
		if card.PIN == 0 || card.PIN > 999999 {
			fmt.Fprintf(&b, " %-*v", widths[7], "-")
		} else {
			fmt.Fprintf(&b, " %-*v", widths[7], card.PIN)
		}
	}

	if c.withFirstCard {
		if card.FirstCard.IsZero() {
			fmt.Fprintf(&b, " %-*v", widths[8], "-")
		} else {
			fmt.Fprintf(&b, " %-*v", widths[8], card.FirstCard)
		}
	}

	return b.String()
}

func (c *CompareACL) parseArgs() error {
	flagset := flag.NewFlagSet("", flag.ExitOnError)
	withPIN := flagset.Bool("with-pin", false, "Include card keypad PIN code when comparing ACLs")
	withFirstCard := flagset.Bool("with-firstcard", false, "Include any first-card privileges when comparing ACLs")
	file := ""
	rptfile := ""
	args := flag.Args()[1:]

	flagset.Parse(args)

	// ... file
	if len(flagset.Args()) > 0 {
		file = flagset.Arg(0)
		stat, err := os.Stat(file)
		if err != nil && os.IsNotExist(err) {
			return fmt.Errorf("file '%s' does not exist", file)
		} else if err != nil {
			return err
		} else if err == nil && stat.Mode().IsDir() {
			return fmt.Errorf("file '%s' is a directory", file)
		} else if err == nil && !stat.Mode().IsRegular() {
			return fmt.Errorf("file '%s' is not a real file", file)
		}
	}

	// ... report file
	if len(flagset.Args()) > 1 {
		rptfile = flagset.Arg(1)
		stat, err := os.Stat(rptfile)
		if err != nil && !os.IsNotExist(err) {
			return err
		} else if err == nil && stat.Mode().IsDir() {
			return fmt.Errorf("file '%s' is a directory", rptfile)
		} else if err == nil && !stat.Mode().IsRegular() {
			return fmt.Errorf("file '%s' is not a real file", rptfile)
		}
	}

	c.file = file
	c.rptfile = rptfile
	c.withPIN = *withPIN
	c.withFirstCard = *withFirstCard

	return nil
}

func (c *CompareACL) CLI() string {
	return "compare-acl"
}

func (c *CompareACL) Description() string {
	return "Compares the card lists in the configured controllers to an authoritative access control list from a TSV file"
}

func (c *CompareACL) Usage() string {
	return "<TSV file> [<report file>]"
}

func (c *CompareACL) Help() {
	fmt.Println("Usage: uhppoted-cli [options] compare-acl <TSV file> <report file>")
	fmt.Println()
	fmt.Println(" Compares the card lists in the configurated controllers to the authoritative access control list in the TSV file")
	fmt.Println(" Duplicate card numbers are ignored (with a warning message)")
	fmt.Println()
	fmt.Println("  <TSV file>    (required) TSV file with access control list")
	fmt.Println()
	fmt.Println("                The TSV file should conform to the following format:")
	fmt.Println("                Card Number<tab>From<tab>To<tab>Front Door<tab>Back Door<tab> ...")
	fmt.Println("                123456789<tab>2023-01-01<tab>2023-12-31<tab>Y<tab>N<tab> ...")
	fmt.Println("                987654321<tab>2023-03-05<tab>2023-11-15<tab>N<tab>N<tab> ...")
	fmt.Println()
	fmt.Println("                'Front Door', 'Back Door', etc should match the door labels in the configuration file.")
	fmt.Println("                The CLI will compare the access control permissions across all the controllers listed.")
	fmt.Println()
	fmt.Println("  <report file> (optional) file to which to write the 'compare' report. Defaults to stdout if not provided")
	fmt.Println()
	fmt.Println("  Options:")
	fmt.Println()
	fmt.Println("    --config  File path for the 'conf' file containing the controller configuration")
	fmt.Printf("              (defaults to %s)\n", config.DefaultConfig)
	fmt.Println("    --debug   Displays internal information for diagnosing errors")
	fmt.Println()
	fmt.Println("    --with-pin       Includes the card keypad PIN code when comparing ACLs.")
	fmt.Println("    --with-firstcard Includes any first-card privileges when comparing ACLs.")
	fmt.Println()
	fmt.Println("               The TSV file with PIN should conform to the following format:")
	fmt.Println("               Card Number<tab>PIN<tab>From<tab>To<tab>Front Door<tab>Back Door<tab> ... FirstCard")
	fmt.Println("               123456789<tab>0<tab>2023-01-01<tab>2023-12-31<tab>Y<tab>N<tab> ...")
	fmt.Println("               987654321<tab>7531<tab>2023-03-05<tab>2023-11-15<tab>N<tab>N<tab> ...")
	fmt.Println()
	fmt.Println("  Examples:")
	fmt.Println()
	fmt.Println(`    uhppoted-cli compare-acl "uhppote-2023-03-07.tsv"`)
	fmt.Println(`    uhppoted-cli --debug --config .config compare-acl --with-pin "uhppoted-2026-08-27.tsv"`)
	fmt.Println()
}

// Returns true - configuration is not optional for this command to return valid information.
func (c *CompareACL) RequiresConfig() bool {
	return true
}
