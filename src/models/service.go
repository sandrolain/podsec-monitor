package models

type Config struct {
	WorkdirPath string `env:"WORKDIR_PATH" validate:"required"`
	MinSeverity int    `env:"MIN_SEVERITY" envDefault:"3" validate:"min=0,max=5"`
	VulnLimit   int    `env:"VULN_LIMIT" envDefault:"10" validate:"min=0"`
	CacheTime   uint32 `env:"CACHE_TIME" envDefault:"86400" validate:"min=0"`
	// Pods config
	Namespaces []string `env:"NAMESPACES"`
	// Directory config
	Directories []string `env:"DIRECTORIES"`
	// SMTP config
	SmtpHost     string   `env:"SMTP_HOST" validate:"required,hostname"`
	SmtpPort     int      `env:"SMTP_PORT" validate:"required"`
	SmtpUsername string   `env:"SMTP_USERNAME"`
	SmtpPassword string   `env:"SMTP_PASSWORD"`
	SmtpFrom     string   `env:"SMTP_FROM" validate:"required,email"`
	SmtpTo       []string `env:"SMTP_TO" validate:"required"`
}
