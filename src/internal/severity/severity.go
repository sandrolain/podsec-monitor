package severity

var severityIndexes = map[string]int{
	"Unknown":    0,
	"Negligible": 1,
	"Low":        2,
	"Medium":     3,
	"High":       4,
	"Critical":   5,
}

var severityEmojii = map[string]string{
	"Unknown":    "❓",
	"Negligible": "ℹ️",
	"Low":        "🩹",
	"Medium":     "⚠️",
	"High":       "🚨",
	"Critical":   "🔥",
}

func GetSeverityIndex(severity string) int {
	return severityIndexes[severity]
}

func GetSeverityEmoji(severity string) string {
	return severityEmojii[severity]
}
