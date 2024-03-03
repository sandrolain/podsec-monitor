package models

type Config struct {
	WorkdirPath string   `env:"WORKDIR_PATH" validate:"required"`
	Namespaces  []string `env:"NAMESPACES" validate:"required"`
	MinSeverity int      `env:"MIN_SEVERITY" envDefault:"3" validate:"min=0,max=5"`
}
