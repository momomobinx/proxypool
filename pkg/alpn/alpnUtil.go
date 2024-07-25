package alpn

import "strings"

func FormatAlpnArray(alpns []string) (result []string) {
	for _, str := range alpns {
		if strings.Contains(str, ",") {
			subStrs := strings.Split(str, ",")
			result = append(result, subStrs...)
		} else {
			result = append(result, str)
		}
	}
	return
}
