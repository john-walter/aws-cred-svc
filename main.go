package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"net/http"
	"time"
	"strconv"
	"strings"
	"sync"
	"regexp"
	"github.com/gen2brain/dlgs"
	"encoding/json"
	"github.com/go-ini/ini"
	"github.com/gorilla/mux"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/stscreds"
 	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"path/filepath"
)

var credentialsConf = map[string]aws.Config{}
var credentialsSts = 	map[string]aws.Credentials{}
var credentialsArn = map[string]string{}
var credentialProfiles = []string{}
var defaultProfileName = ""
var defaultProfileRoute = "latest"

var arnMatch = regexp.MustCompile("arn:aws:iam::\\S*")
var sessionMutex sync.Mutex

func main() {
	stscreds.DefaultDuration = time.Minute * 60
	cfg, err := ini.Load(SharedCredentialsFilename())
	if err != nil {
		os.Exit(1)
	}
	for _, profileName := range cfg.SectionStrings() {
		if profileName != defaultProfileRoute {
			credentialProfiles = append(credentialProfiles, strings.Replace(profileName, "profile ", "", -1))
		}
	}
	WebSvr()
	Repl()
}

func SharedCredentialsFilename() string {
	return filepath.Join(UserHomeDir(), ".aws", "credentials")
}

func UserHomeDir() string {
	if runtime.GOOS == "windows" { // Windows
		return os.Getenv("USERPROFILE")
	}

	// *nix
	return os.Getenv("HOME")
}

func WebSvr() {
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/{profile}/meta-data/instance-id", MockInstanceId)
	router.HandleFunc("/{profile}/meta-data/local-hostname", Localhost)
	router.HandleFunc("/{profile}/meta-data/hostname", Localhost)
	router.HandleFunc("/{profile}/meta-data/public-hostname", Localhost)
	router.HandleFunc("/{profile}/meta-data/mac", MockMac)
	router.HandleFunc("/{profile}/meta-data/network/interfaces/macs/00:00:00:00:00:00/vpc-id", MockVpc)
	router.HandleFunc("/{profile}/meta-data/local-ipv4", Loopback)
	router.HandleFunc("/{profile}/meta-data/instance-type", MockInstanceType)
	router.HandleFunc("/{profile}/dynamic/instance-identity/document", MockIdentityDoc)
	router.HandleFunc("/{profile}/meta-data/iam/security-credentials/", DefaultProfile)
	router.HandleFunc("/{profile}/meta-data/iam/security-credentials/default", PresentCredentials)
	router.HandleFunc("/{profile}/use", SetDefaultProfile)
	go func() {
		log.Fatal(http.ListenAndServe("169.254.169.254:12319", router))
	}()
}

func Repl() {
	var input string
	for true {
		fmt.Println("\nSelect an AWS profile: \n")
		for idx, profileName := range credentialProfiles {
			activeIndicator := func() string { if profileName == defaultProfileName { return " (active)" } else { return "" } }
			fmt.Println(strconv.FormatInt(int64(idx), 10) + " " + profileName + activeIndicator())
		}
		fmt.Print("\n> ")
		fmt.Scanln(&input)
		profileIdx, _ := strconv.ParseInt(input, 10, 0)
		if 0 <= profileIdx && int(profileIdx) < len(credentialProfiles) {
			defaultProfileName = credentialProfiles[profileIdx]
			Session(defaultProfileName)
		}
	}
}

func Session(profileName string) aws.Credentials {
	session, gotSession := credentialsSts[profileName]

	isNewSession := !gotSession || session.Expired()
	
	if isNewSession {
		sessionMutex.Lock()
		session, gotSession = credentialsSts[profileName]
	}

	if !gotSession || session.Expired() {
		var mfaEnabled bool
		var cfg aws.Config
		if gotSession {
			cfg = credentialsConf[profileName]
		} else {
			cfg, _ = external.LoadDefaultAWSConfig(
				external.WithMFATokenFunc(func() (string, error) {
					mfaEnabled = true
					code, _, err := dlgs.Password("Password", "Enter your AWS MFA code: ")
					return code, err
				}),
				external.WithSharedConfigProfile(profileName),
			)
		}
		if &cfg != nil {
			// This is hacky and needs a better solution - parse the raw credentialprovider string output and look for a role ARN
			roleArnMatch := arnMatch.FindAllString(fmt.Sprintf("%v", cfg.Credentials), 1)
			// keep looping around cred retrieval three times - in case someone just entered their mfa code wrong
			for i := 0; i < 3; i++ {
				sessionPre, credFail := cfg.Credentials.Retrieve()
				if 0 < len(roleArnMatch) && credFail == nil && sessionPre.CanExpire {
					session = sessionPre
					credentialsConf[profileName] = cfg
					credentialsSts[profileName] = session
					credentialsArn[profileName] = roleArnMatch[0]
					break
				} else if !mfaEnabled {
					break
				}
			}
		}
	} else if session.Expires.UTC().Sub(time.Now().UTC()).Minutes() < 20 {
		newConf := credentialsConf[profileName].Copy()
		newConf.Credentials = aws.NewStaticCredentialsProvider(session.AccessKeyID, session.SecretAccessKey, session.SessionToken)
		session, _ = stscreds.NewAssumeRoleProvider(sts.New(newConf), credentialsArn[profileName]).Retrieve()
		credentialsSts[profileName] = session
	}
	if isNewSession {
		sessionMutex.Unlock()
	}
	return session
}

func MockInstanceId(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "i-1234567890abcdef0")
}

func DefaultProfile(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "default")
}

func Localhost(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "localhost")
}

func Loopback(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "127.0.0.1")
}

func MockMac(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "00:00:00:00:00:00")
}

func MockVpc(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "vpc-0000")
}

func MockInstanceType(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "m3.medium")
}

func MockIdentityDoc(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	if vars["profile"] == defaultProfileRoute && defaultProfileName != "" {
		vars["profile"] = defaultProfileName
	}
	cfg, gotConf := credentialsConf[vars["profile"]]

	region := "us-east-1"
	if gotConf {
		region = cfg.Region
	}

	ident, _ := json.Marshal(map[string]string{
		"privateIp": "127.0.0.1",
		"availabilityZone": region + "a",
		"devpayProductCodes": "",
		"version": "2010-08-31",
		"instanceId": "i-1234567890abcdef0",
		"billingProducts": "",
		"instanceType": "m3.medium",
		"architecture": "x86_64",
		"kernelId": "",
		"ramdiskId": "",
		"imageId": "ami-1562d075",
		"pendingTime": "2017-03-13T17:13:27Z",
		"region": region,
 	})
	fmt.Fprint(w, string(ident))
}

func PresentCredentials(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	if vars["profile"] == defaultProfileRoute && defaultProfileName != "" {
		vars["profile"] = defaultProfileName
	}
	session := Session(vars["profile"])

	if &session != nil && session.HasKeys() {
		creds, _ := json.Marshal(map[string]string{
			"AccessKeyId": session.AccessKeyID,
			"Code": "Success",
			"Expiration": session.Expires.Format("2006-01-02T15:04:05Z"),
			"LastUpdated": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			"SecretAccessKey": session.SecretAccessKey,
			"Token": session.SessionToken,
			"Type": "AWS-HMAC",
		})
		fmt.Fprint(w, string(creds))
	} else {
		fmt.Fprint(w, "{}")
	}
}

func SetDefaultProfile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	_, gotSession := credentialsSts[vars["profile"]]
	if gotSession {
		defaultProfileName = vars["profile"]
		PresentCredentials(w, r)
	} else {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "")
	}
}
