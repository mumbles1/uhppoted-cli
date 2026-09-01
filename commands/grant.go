package commands

import (
	"flag"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"codeberg.org/uhppoted/uhppoted-core/types"
	"codeberg.org/uhppoted/uhppoted-lib/acl"
	"codeberg.org/uhppoted/uhppoted-lib/config"
)

var GrantCmd = Grant{}

type Grant struct {
}

func (c *Grant) Execute(ctx Context) error {
	if ctx.config == nil {
		return fmt.Errorf("grant requires a valid configuration file")
	}

	cardNumber, err := getUint32(1, "missing card number", "invalid card number: %v")
	if err != nil {
		return err
	}

	from, err := getDate(2, "missing start date", "invalid start date: %v")
	if err != nil {
		return err
	}

	to, err := getDate(3, "missing end date", "invalid end date: %v")
	if err != nil {
		return err
	}

	// ... time profile ?
	var re = regexp.MustCompile("[0-9]+")
	var profile = 0
	var firstcard = acl.FirstCardUnknown
	var doors []string

	if len(flag.Args()) > 5 && re.MatchString(flag.Arg(4)) && flag.Arg(5) != "--firstcard" && flag.Arg(5) != "--first-card" {
		if v, err := strconv.Atoi(flag.Arg(4)); err != nil {
			return err
		} else if v < 2 || v > 254 {
			return fmt.Errorf("invalid time profile ID (%v) - valid range is from 2 to 254", v)
		} else {
			profile = v
		}

		if v, err := c.getDoors(5); err != nil {
			return err
		} else {
			doors = v
		}
	} else if doors, err = c.getDoors(4); err != nil {
		return err
	}

	if arg := flag.Args()[len(flag.Args())-1]; arg == "--first-card" || arg == "--firstcard" {
		firstcard = acl.FirstCardGranted
	}

	err = acl.Grant(ctx.uhppote, ctx.devices, cardNumber, types.Date(*from), types.Date(*to), profile, doors, firstcard)
	if err != nil {
		return err
	}

	fmt.Println(" ... ok")

	return nil
}

func (c *Grant) getDoors(ix int) ([]string, error) {
	doors := []string{}
	args := []string{}

	for ; ix < len(flag.Args()); ix++ {
		arg := flag.Arg(ix)

		if arg == "--firstcard" || arg == "--first-card" {
			break
		}

		args = append(args, arg)
	}

	s := strings.Join(args, ",")
	tokens := strings.SplitSeq(s, ",")

	for t := range tokens {
		if d := strings.ToLower(strings.ReplaceAll(t, " ", "")); d != "" {
			doors = append(doors, strings.TrimSpace(t))
		}
	}

	return doors, nil
}

func (c *Grant) CLI() string {
	return "grant"
}

func (c *Grant) Description() string {
	return "Grants a card access to a door (or doors)"
}

func (c *Grant) Usage() string {
	return "<card number> <start date> <end date> [profile] <doors>"
}

func (c *Grant) Help() {
	fmt.Println("Usage: uhppoted-cli [options] grant <card number> <start date> <end date> <profile> <doors> <--firstcard>")
	fmt.Println()
	fmt.Println(" Sets the access permissions for a card")
	fmt.Println()
	fmt.Println("  <card number>    (required) card number")
	fmt.Println("  <start date>     (required) start date YYYY-MM-DD")
	fmt.Println("  <end date>       (required) end date   YYYY-MM-DD")
	fmt.Println("  <profile>        (optional) predefined time profile, in the range [2..254]")
	fmt.Println("  <doors>          (required) comma separated list of permitted doors e.g. Front Door, Workshop")
	fmt.Println("                              Doors are case- and space insensitive and correspond to the doors")
	fmt.Println("                              defined in the config file. The pseudo-door ALL will grant the")
	fmt.Println("                              card access to all doors across all configured configured")
	fmt.Println()
	fmt.Println("                              N.B. 'grant' permissions are ADDED to the existing permissions for")
	fmt.Println("                                    a card. Use 'revoke' to remove unwanted permissions.")
	fmt.Println("                                    Also, the 'from' and 'to' dates for a card are WIDENED to")
	fmt.Println("                                    the earliest 'from' date and latest 'to' date combination")
	fmt.Println("                                    for all records for this card across all controllers.")
	fmt.Println()
	fmt.Println("  <--firstcard>    (optional) grants first-card privilege to all doors to which the card has access.")
	fmt.Println()
	fmt.Println("  Options:")
	fmt.Println()
	fmt.Println("    --config  File path for the 'conf' file containing the controller configuration")
	fmt.Printf("              (defaults to %s)\n", config.DefaultConfig)
	fmt.Println("    --debug   Displays internal information for diagnosing errors")
	fmt.Println()
	fmt.Println("  Examples:")
	fmt.Println()
	fmt.Println("    uhppoted-cli grant 918273645 2020-01-01 2020-12-31 Front Door, Workshop")
	fmt.Println(`    uhppote-cli grant 918273645 2020-01-01 2020-12-31 29 "Front Door, Workshop"`)
	fmt.Println("    uhppoted-cli grant 918273645 2020-01-01 2020-12-31 ALL")
	fmt.Println()
}

// Returns true - configuration is not optional for this command to return valid information.
func (c *Grant) RequiresConfig() bool {
	return true
}
