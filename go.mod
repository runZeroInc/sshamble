module github.com/runZeroInc/sshamble

go 1.24.0

// NOTE: Uncomment to test with a development version of excrypto
replace github.com/runZeroInc/excrypto => ../excrypto

require (
	github.com/google/go-cmp v0.7.0
	github.com/logrusorgru/aurora/v3 v3.0.0
	github.com/mmcloughlin/professor v0.0.0-20170922221822-6b97112ab8b3
	github.com/runZeroInc/excrypto v0.0.0-20260118082313-6bbe61bcc984
	github.com/sirupsen/logrus v1.9.4
	github.com/spf13/cobra v1.10.2
	github.com/spf13/viper v1.21.0
	github.com/ulikunitz/xz v0.5.15
	golang.org/x/crypto v0.47.0
	golang.org/x/term v0.39.0
	gonum.org/v1/gonum v0.17.0
)

require (
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/sagikazarmark/locafero v0.12.0 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/weppos/publicsuffix-go v0.50.2 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
)
