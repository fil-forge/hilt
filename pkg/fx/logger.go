package fx

import (
	"fmt"

	"github.com/fil-forge/hilt/pkg/config"
	"go.uber.org/fx"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// LoggerModule provides the zap logger.
var LoggerModule = fx.Module("logger", fx.Provide(NewLogger))

// NewLogger creates a zap logger based on the configured log level.
func NewLogger(cfg config.LogConfig) (*zap.Logger, error) {
	var level zapcore.Level
	err := level.UnmarshalText([]byte(cfg.Level))
	if err != nil {
		return nil, fmt.Errorf("parsing log level: %w", err)
	}

	var logCfg zap.Config
	if level == zapcore.DebugLevel {
		logCfg = zap.NewDevelopmentConfig()
	} else {
		logCfg = zap.NewProductionConfig()
	}
	logCfg.Level = zap.NewAtomicLevelAt(level)

	logger, err := logCfg.Build()
	if err != nil {
		return nil, fmt.Errorf("creating logger: %w", err)
	}
	return logger, nil
}
