module github.com/cloudfoundry/stratos/src/jetstream

go 1.22

toolchain go1.24.0

replace (
	github.com/cloudfoundry/stratos/src/jetstream/api => ./api
	github.com/cloudfoundry/stratos/src/jetstream/api/config => ./api/config
	github.com/cloudfoundry/stratos/src/jetstream/crypto => ./crypto
	github.com/cloudfoundry/stratos/src/jetstream/docs => ./docs
	github.com/cloudfoundry/stratos/src/jetstream/plugins/cfapppush => ./plugins/cfapppush
	github.com/cloudfoundry/stratos/src/jetstream/plugins/cloudfoundry => ./plugins/cloudfoundry
	github.com/cloudfoundry/stratos/src/jetstream/plugins/kubernetes => ./plugins/kubernetes
	github.com/cloudfoundry/stratos/src/jetstream/plugins/kubernetes/auth => ./plugins/kubernetes/auth
	github.com/cloudfoundry/stratos/src/jetstream/plugins/kubernetes/terminal => ./plugins/kubernetes/terminal
	github.com/cloudfoundry/stratos/src/jetstream/plugins/monocular => ./plugins/monocular
)

// ported from plugins/kubernetes
replace (
	code.cloudfoundry.org/go-log-cache => code.cloudfoundry.org/go-log-cache v1.0.1-0.20211011162012-ede82a99d3cc
	github.com/SermoDigital/jose => github.com/SermoDigital/jose v0.9.2-0.20180104203859-803625baeddc
	github.com/sabhiram/go-gitignore => github.com/sabhiram/go-gitignore v0.0.0-20180611051255-d3107576ba94
	github.com/vito/go-interact => github.com/vito/go-interact v1.0.0
)

require (
	code.cloudfoundry.org/go-log-cache v1.0.1-0.20230224210401-5e305670b626
	code.cloudfoundry.org/go-loggregator/v8 v8.0.5
	github.com/antonlindstrom/pgstore v0.0.0-20220421113606-e3a6e3fed12a
	github.com/cf-stratos/mysqlstore v0.0.0-20170822100912-304308519d13
	github.com/cloudfoundry-community/go-cfenv v1.18.0
	github.com/cloudfoundry/noaa/v2 v2.3.0
	github.com/cloudfoundry/sonde-go v0.0.0-20230911203642-fa89d986ae20
	github.com/cloudfoundry/stratos/src/jetstream/api v0.0.0-00010101000000-000000000000
	github.com/cloudfoundry/stratos/src/jetstream/plugins/kubernetes/auth v0.0.0-00010101000000-000000000000
	github.com/domodwyer/mailyak v3.1.1+incompatible
	github.com/go-sql-driver/mysql v1.7.1
	github.com/golang/mock v1.6.0
	github.com/gorilla/context v1.1.1
	github.com/gorilla/securecookie v1.1.1
	github.com/gorilla/sessions v1.2.1
	github.com/gorilla/websocket v1.5.0
	github.com/govau/cf-common v0.0.7
	github.com/kat-co/vala v0.0.0-20170210184112-42e1d8b61f12
	github.com/labstack/echo/v4 v4.11.3
	github.com/mattn/go-sqlite3 v1.14.17
	github.com/nwmac/sqlitestore v0.0.0-20180824125213-7d2ab221fb3f
	github.com/pressly/goose v2.7.0+incompatible
	github.com/samber/lo v1.38.1
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.9.3
	github.com/smartystreets/goconvey v1.8.1
	github.com/swaggo/echo-swagger v1.4.0
	golang.org/x/crypto v0.32.0
	gopkg.in/DATA-DOG/go-sqlmock.v1 v1.3.0
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/client-go v0.29.0
)

require (
	github.com/KyleBanks/depth v1.2.1 // indirect
	github.com/SermoDigital/jose v0.9.2-0.20161205224733-f6df55f235c2 // indirect
	github.com/aws/aws-sdk-go v1.44.324 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blang/semver v3.5.1+incompatible // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/cloudfoundry/stratos/src/jetstream/plugins/kubernetes v0.0.0-20210416105629-f34f428ca775 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/go-logr/logr v1.3.0 // indirect
	github.com/go-openapi/jsonpointer v0.19.6 // indirect
	github.com/go-openapi/jsonreference v0.20.2 // indirect
	github.com/go-openapi/spec v0.20.4 // indirect
	github.com/go-openapi/swag v0.22.3 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/gofrs/flock v0.8.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/gopherjs/gopherjs v1.17.2 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.16.0 // indirect
	github.com/imdario/mergo v0.3.13 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/jtolds/gls v4.20.0+incompatible // indirect
	github.com/labstack/gommon v0.4.0 // indirect
	github.com/lib/pq v1.10.9 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/mitchellh/mapstructure v1.4.1 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/nxadm/tail v1.4.11 // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_golang v1.16.0 // indirect
	github.com/prometheus/client_model v0.4.0 // indirect
	github.com/prometheus/common v0.44.0 // indirect
	github.com/prometheus/procfs v0.10.1 // indirect
	github.com/sclevine/spec v1.4.0 // indirect
	github.com/smarty/assertions v1.15.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/swaggo/files/v2 v2.0.0 // indirect
	github.com/swaggo/swag v1.16.1 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	golang.org/x/exp v0.0.0-20220722155223-a9213eeb770e // indirect
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/oauth2 v0.12.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
	golang.org/x/term v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.org/x/tools v0.21.1-0.20240508182429-e35e4ccd0d2d // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/genproto v0.0.0-20231002182017-d307bd883b97 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20231002182017-d307bd883b97 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231002182017-d307bd883b97 // indirect
	google.golang.org/grpc v1.58.3 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/apimachinery v0.29.0 // indirect
	k8s.io/klog/v2 v2.110.1 // indirect
	k8s.io/utils v0.0.0-20230726121419-3b25d923346b // indirect
	sigs.k8s.io/aws-iam-authenticator v0.6.11 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.4.1 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)
