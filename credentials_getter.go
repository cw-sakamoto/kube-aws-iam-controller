package main

import (
	"fmt"
	"strings"
	"time"
	"crypto/md5"
	"encoding/hex"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
)

const (
	arnPrefix = "arn:aws:iam::"
)

// CredentialsGetter can get credentials.
type CredentialsGetter interface {
	Get(role string, sessionDuration time.Duration) (*Credentials, error)
}

// Credentials defines fecthed credentials including expiration time.
type Credentials struct {
	RoleARN         string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

// STSCredentialsGetter is a credentials getter for getting credentials from
// STS.
type STSCredentialsGetter struct {
	svc         stsiface.STSAPI
	baseRoleARN string
}

// NewSTSCredentialsGetter initializes a new STS based credentials fetcher.
func NewSTSCredentialsGetter(sess *session.Session, baseRoleARN string) *STSCredentialsGetter {
	return &STSCredentialsGetter{
		svc:         sts.New(sess),
		baseRoleARN: baseRoleARN,
	}
}

// Get gets new credentials for the specified role. The credentials are fetched
// via STS.
func (c *STSCredentialsGetter) Get(role string, sessionDuration time.Duration) (*Credentials, error) {
	roleARN := c.baseRoleARN + role
	if strings.HasPrefix(role, arnPrefix) {
		roleARN = role
	}
	roleSessionName := hashRoleARN(roleARN)

	params := &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleARN),
		RoleSessionName: aws.String(roleSessionName),
		DurationSeconds: aws.Int64(int64(sessionDuration.Seconds())),
	}

	resp, err := c.svc.AssumeRole(params)
	if err != nil {
		return nil, err
	}

	return &Credentials{
		RoleARN:         roleARN,
		AccessKeyID:     aws.StringValue(resp.Credentials.AccessKeyId),
		SecretAccessKey: aws.StringValue(resp.Credentials.SecretAccessKey),
		SessionToken:    aws.StringValue(resp.Credentials.SessionToken),
		Expiration:      aws.TimeValue(resp.Credentials.Expiration),
	}, nil
}

// GetBaseRoleARN gets base role ARN from EC2 metadata service.
func GetBaseRoleARN(sess *session.Session) (string, error) {
	metadata := ec2metadata.New(sess)

	iamInfo, err := metadata.IAMInfo()
	if err != nil {
		return "", err
	}

	arn := strings.Replace(iamInfo.InstanceProfileArn, "instance-profile", "role", 1)
	baseRoleARN := strings.Split(arn, "/")
	if len(baseRoleARN) < 2 {
		return "", fmt.Errorf("failed to determine BaseRoleARN")
	}

	return fmt.Sprintf("%s/", baseRoleARN[0]), nil
}

func hashRoleARN(roleARN string) string {
	// session name is must unique
	t := time.Now().Format(time.RFC3339Nano)
	hash := md5.Sum([]byte(roleARN + t))
	return hex.EncodeToString(hash[:])
}
