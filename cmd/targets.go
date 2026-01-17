package cmd

import (
	"fmt"
	"math"
	"math/rand/v2"
	"net/netip"
	"strconv"
	"strings"
)

func parseTargets(input string) ([]string, error) {
	res := []string{}
	for target := range strings.FieldsSeq(strings.ReplaceAll(input, ",", " ")) {
		target = strings.ToLower(strings.TrimSpace(target))
		if target == "" {
			continue
		}

		user, notUser, hasUser := strings.Cut(target, "@")
		if hasUser {
			target = notUser
		}

		if target == "" {
			continue
		}

		if !strings.Contains(target, "/") {
			if hasUser {
				res = append(res, user+"@"+target)
			} else {
				res = append(res, target)
			}
			continue
		}

		// Expand CIDRs
		prefix, err := netip.ParsePrefix(target)
		if err != nil {
			return res, fmt.Errorf("bad prefix %s: %v", target, err)
		}
		base := prefix.Masked().Addr()
		if !base.Is4() {
			return res, fmt.Errorf("ipv6 prefixes are not supported %s: %v", target, err)
		}
		acnt := uint64(math.Pow(2, float64(32-prefix.Bits())))
		for i := uint64(1); i <= acnt; i++ {
			if hasUser {
				res = append(res, user+"@"+base.String())
			} else {
				res = append(res, base.String())
			}
			res = append(res, base.String())
			base = base.Next()
		}
	}
	// Randomize the target order
	rand.Shuffle(len(res), func(i, j int) {
		res[i], res[j] = res[j], res[i]
	})
	return res, nil
}

// parsePorts turns a comma-delimited port list into an array
func parsePorts(pspec string) ([]int, error) {
	res := []int{}

	// Use a map to dedup and shuffle ports
	ports := make(map[int]bool)

	bits := strings.SplitSeq(pspec, ",")
	for bit := range bits {
		bit = strings.TrimSpace(bit)

		if bit == "" {
			continue
		}

		// Split based on dash
		prange := strings.Split(bit, "-")

		// Scan all ports if the specifier is a single dash
		if bit == "-" {
			prange = []string{"1", "65535"}
		}

		// No port range
		if len(prange) == 1 {
			pnum, err := strconv.Atoi(bit)
			if err != nil || !validPort(pnum) {
				return res, fmt.Errorf("invalid port %s", bit)
			}
			// Record the valid port
			ports[pnum] = true
			continue
		}

		if len(prange) != 2 {
			return res, fmt.Errorf("invalid port range %s (%d)", prange, len(prange))
		}

		pstart, err := strconv.Atoi(prange[0])
		if err != nil || !validPort(pstart) {
			return res, fmt.Errorf("invalid start port %d", pstart)
		}

		pstop, err := strconv.Atoi(prange[1])
		if err != nil || !validPort(pstop) {
			return res, fmt.Errorf("invalid stop port %d", pstop)
		}

		if pstart > pstop {
			return res, fmt.Errorf("invalid port range %d-%d", pstart, pstop)
		}

		for pnum := pstart; pnum <= pstop; pnum++ {
			ports[pnum] = true
		}
	}

	// Create the res from the map
	for port := range ports {
		res = append(res, port)
	}

	// Randomize the results
	rand.Shuffle(len(res), func(i, j int) {
		res[i], res[j] = res[j], res[i]
	})
	return res, nil
}

// validPort determines if a port number is valid
func validPort(pnum int) bool {
	if pnum < 0 || pnum > 65535 {
		return false
	}
	return true
}
