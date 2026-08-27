package commands

import (
	"fmt"
	"sort"
	"strings"

	"codeberg.org/uhppoted/uhppoted-lib/acl"
	"codeberg.org/uhppoted/uhppoted-lib/config"
)

var ShowCmd = Show{}

type Show struct {
}

func (c *Show) Execute(ctx Context) error {
	if ctx.config == nil {
		return fmt.Errorf("show requires a valid configuration file")
	}

	cardNumber, err := getUint32(1, "Missing card number", "Invalid card number: %v")
	if err != nil {
		return err
	}

	permissions, err := acl.GetCard(ctx.uhppote, ctx.devices, cardNumber)
	if err != nil {
		return err
	}

	doors := []string{}
	width := 0
	profiles := false
	for k, v := range permissions {
		doors = append(doors, k)

		if width < len([]rune(k)) {
			width = len([]rune(k))
		}

		if v.Profile >= 2 && v.Profile <= 254 {
			profiles = true
		}
	}

	sort.Slice(doors, func(i, j int) bool {
		p := strings.ToLower(strings.ReplaceAll(doors[i], " ", ""))
		q := strings.ToLower(strings.ReplaceAll(doors[j], " ", ""))
		return p < q
	})

	fmt.Println()
	for _, door := range doors {
		v := permissions[door]
		b := strings.Builder{}

		fmt.Fprintf(&b, "%-[1]*s  %v  %v", width, door, v.From, v.To)

		if v.Profile >= 2 && v.Profile <= 254 {
			fmt.Fprintf(&b, "  %-3v", v.Profile)
		} else if profiles {
			fmt.Fprintf(&b, "  %-3v", "")
		}

		if v.FirstCard {
			b.WriteString("  firstcard")
		}

		fmt.Printf("%v\n", b.String())
	}
	fmt.Println()

	return nil
}

func (c *Show) CLI() string {
	return "show"
}

func (c *Show) Description() string {
	return "Lists the access permissions for a card"
}

func (c *Show) Usage() string {
	return "<card number>"
}

func (c *Show) Help() {
	fmt.Println("Usage: uhppoted-cli [options] show <card number>")
	fmt.Println()
	fmt.Println(" Lists the access permissions for a card")
	fmt.Println()
	fmt.Println("  <card number>    (required) card number")
	fmt.Println()
	fmt.Println("  Options:")
	fmt.Println()
	fmt.Println("    --config  File path for the 'conf' file containing the controller configuration")
	fmt.Printf("              (defaults to %s)\n", config.DefaultConfig)
	fmt.Println("    --debug   Displays internal information for diagnosing errors")
	fmt.Println()
	fmt.Println("  Examples:")
	fmt.Println()
	fmt.Println("    uhppoted-cli show 918273645")
	fmt.Println()
}

// Returns true - configuration is not optional for this command to return valid information.
func (c *Show) RequiresConfig() bool {
	return true
}
