package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/cucumber/godog"
	// Neded so the "go run" command can execute.
	_ "github.com/enterprise-contract/ec-cli/cmd"
)

const (
	policyInputFilename  = "input.json"
	policyConfigFilename = "policy.json"
)

// Todo:
// //go:embed samples/*
// var samples embed.FS
var (
	//go:embed samples/policy-input-golden-container.json
	sampleGCPolicyInput string
	//go:embed samples/clamav-task.json
	sampleClamAVTask string
	//go:embed samples/v02-sample-attestation.json
	sampleV02Attestation string
	//go:embed samples/v1-sample-attestation.json
	sampleV1Attestation string
)

type testStateKey struct{}

type testState struct {
	tempDir              string
	variables            map[string]string
	report               report
	cliPath              string
	inputFileName        string
	configFileName       string
	acceptanceModulePath string
	stdout               string
}

// Types used for parsing violations and warnings from report
type (
	result struct {
		Message  string                 `json:"msg"`
		Metadata map[string]interface{} `json:"metadata,omitempty"`
	}

	input struct {
		Violations []result `json:"violations"`
		Warnings   []result `json:"warnings"`
	}

	report struct {
		FilePaths []input `json:"filepaths"`
	}
)

func writeSampleGCPolicyInput(ctx context.Context, sampleName string) (context.Context, error) {
	ts, err := getTestState(ctx)
	if err != nil {
		return ctx, fmt.Errorf("writeSampleGCPolicyInput get test state: %w", err)
	}

	f, err := os.Create(ts.inputFileName)
	if err != nil {
		return ctx, fmt.Errorf("creating %s file: %w", ts.inputFileName, err)
	}
	defer f.Close()

	var content string
	switch sampleName {
	case "golden-container":
		content = sampleGCPolicyInput
	case "clamav-task":
		content = sampleClamAVTask
	case "v02-sample-attestation":
		content = sampleV02Attestation
	case "v1-sample-attestation":
		content = sampleV1Attestation
	default:
		return ctx, fmt.Errorf("%q is not a known sample name", sampleName)
	}

	if _, err := f.WriteString(content); err != nil {
		return ctx, fmt.Errorf("writing %s file: %w", ts.inputFileName, err)
	}

	return ctx, nil
}

func writePolicyConfig(ctx context.Context, config *godog.DocString) (context.Context, error) {
	ts, err := getTestState(ctx)
	if err != nil {
		return ctx, fmt.Errorf("writePolicyConfig get test state: %w", err)
	}

	f, err := os.Create(ts.configFileName)
	if err != nil {
		return ctx, fmt.Errorf("creating %s file: %w", ts.configFileName, err)
	}
	defer f.Close()

	content := replaceVariables(config.Content, ts.variables)

	if _, err := f.WriteString(content); err != nil {
		return ctx, fmt.Errorf("writing %s file: %w", ts.configFileName, err)
	}

	return ctx, nil
}

func validateInputWithPolicyConfig(ctx context.Context) (context.Context, error) {
	ts, err := getTestState(ctx)
	if err != nil {
		return ctx, fmt.Errorf("validateInputWithPolicyConfig get test state: %w", err)
	}

	cmd := exec.Command(
		"go",
		"run",
		"github.com/enterprise-contract/ec-cli",
		"validate",
		"input",
		"--file",
		ts.inputFileName,
		"--policy",
		ts.configFileName,
		"--strict=false",
	)
	cmd.Dir = ts.acceptanceModulePath

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return ctx, fmt.Errorf("running ec validate input: %w\n%s", err, stderr.String())
	}

	var r report
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		return ctx, fmt.Errorf("unmarshalling report: %w", err)
	}
	ts.report = r

	return setTestState(ctx, ts), nil
}

func thereShouldBeNoViolationsInTheResult(ctx context.Context) error {
	ts, err := getTestState(ctx)
	if err != nil {
		return fmt.Errorf("reading test state: %w", err)
	}

	for _, filepath := range ts.report.FilePaths {
		if len(filepath.Violations) != 0 {
			return errors.New(prettifyResults("expected no violations, got:", filepath.Violations))
		}
	}

	return nil
}

func thereShouldBeNoWarningsInTheResult(ctx context.Context) error {
	ts, err := getTestState(ctx)
	if err != nil {
		return fmt.Errorf("reading test state: %w", err)
	}

	for _, filepath := range ts.report.FilePaths {
		if len(filepath.Warnings) != 0 {
			return errors.New(prettifyResults("expected no warnings, got:", filepath.Warnings))
		}
	}

	return nil
}

func opaEval(ctx context.Context, evalString string) (context.Context, error) {
	ts, err := getTestState(ctx)
	if err != nil {
		return ctx, fmt.Errorf("opaEval get test state: %w", err)
	}

	cmd := exec.Command(
		"go",
		"run",
		"github.com/enterprise-contract/ec-cli",
		"opa",
		"eval",
		"--data",
		"./policy", // all the rego
		"--input",
		ts.inputFileName,
		evalString,
	)
	cmd.Dir = ts.variables["GITROOT"]

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return ctx, fmt.Errorf("running ec opa eval: %w\n%s", err, stderr.String())
	}

	ts.stdout = string(stdout.Bytes())

	return setTestState(ctx, ts), nil
}

func theOPAResultJSONShouldBe(ctx context.Context, expectedResult string) error {
	ts, err := getTestState(ctx)
	if err != nil {
		return fmt.Errorf("reading test state: %w", err)
	}

	// Unmarshal the expected result from json so we don't need to worry
	// about formatting diffs
	var expectedResultData any
	err = json.Unmarshal([]byte(expectedResult), &expectedResultData)
	if err != nil {
		return fmt.Errorf("parsing expected result json: %w", err)
	}

	// Marshal it back to consistently indented json
	// Todo maybe: use github.com/yudai/gojsondiff or
	// or github.com/google/go-cmp/cmp to produce helpful diffs
	expected, err := json.MarshalIndent(expectedResultData, "", "  ")
	if err != nil {
		return fmt.Errorf("remarshalling expected result data: %w", err)
	}

	// Unmarshal the actual opa eval result
	// We get something like this on stdout:
	//   {"result":[{"expressions":[{"value": ...}]}]}
	// I think we'll generally have just have one expression and one result,
	// so let's pull that value up so the feature files are a little tidier
	var parsedOutput map[string][]map[string][]map[string]any
	err = json.Unmarshal([]byte(ts.stdout), &parsedOutput)
	if err != nil {
		return fmt.Errorf("unmarshalling opa eval output: %w", err)
	}
	value := parsedOutput["result"][0]["expressions"][0]["value"]

	// Convert the value back to consistently indented json
	actual, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("Problem marshalling opa result value: %w", err)
	}

	if string(expected) != string(actual) {
		return fmt.Errorf("expected:\n%s\n\ngot:\n%s\n", expected, actual)
	}

	return nil
}

func prettifyResults(msg string, results []result) string {
	for _, violation := range results {
		code := violation.Metadata["code"].(string)
		msg += fmt.Sprintf("\n\t%s:\t%s", code, violation.Message)
	}
	return msg
}

func replaceVariables(content string, variables map[string]string) string {
	for name, value := range variables {
		re := regexp.MustCompile(`\$` + name + `\b`)
		content = re.ReplaceAllString(content, value)
	}
	return content
}

func setupScenario(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
	tempDir, err := os.MkdirTemp("", "ec-policies-")
	if err != nil {
		return ctx, fmt.Errorf("setting up scenario: %w", err)
	}

	acceptanceModulePath, err := filepath.Abs(".")
	if err != nil {
		return ctx, fmt.Errorf("getting acceptance module path: %w", err)
	}

	gitroot, err := filepath.Abs("..")
	if err != nil {
		return ctx, fmt.Errorf("getting gitroot: %w", err)
	}

	ts := testState{
		cliPath:              filepath.Join(gitroot, "acceptance/bin/ec"),
		tempDir:              tempDir,
		acceptanceModulePath: acceptanceModulePath,
		inputFileName:        path.Join(tempDir, policyInputFilename),
		configFileName:       path.Join(tempDir, policyConfigFilename),
		variables: map[string]string{
			"GITROOT": gitroot,
		},
	}

	return setTestState(ctx, ts), nil
}

func tearDownScenario(ctx context.Context, sc *godog.Scenario, _ error) (context.Context, error) {
	// Purposely ignore errors here to prevent a tear down error to mask a test error.
	ts, _ := getTestState(ctx)

	if ts.tempDir != "" {
		_ = os.RemoveAll(ts.tempDir)
	}
	return ctx, nil
}

func getTestState(ctx context.Context) (testState, error) {
	ts, ok := ctx.Value(testStateKey{}).(testState)
	if !ok {
		return testState{}, errors.New("test state not set")
	}
	return ts, nil
}

func setTestState(ctx context.Context, ts testState) context.Context {
	return context.WithValue(ctx, testStateKey{}, ts)
}

func InitializeScenario(sc *godog.ScenarioContext) {
	sc.Before(setupScenario)

	sc.Step(`^a sample policy input "([^"]*)"$`, writeSampleGCPolicyInput)
	sc.Step(`^a policy config:$`, writePolicyConfig)
	sc.Step(`^input is validated$`, validateInputWithPolicyConfig)
	sc.Step(`^there should be no violations in the result$`, thereShouldBeNoViolationsInTheResult)
	sc.Step(`^there should be no warnings in the result$`, thereShouldBeNoWarningsInTheResult)

	sc.Step(`^we opa eval$`, opaEval)
	sc.Step(`^the opa result json should be$`, theOPAResultJSONShouldBe)

	sc.After(tearDownScenario)
}

func TestFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"features"},
			TestingT: t, // Testing instance that will run subtests.
		},
	}

	if suite.Run() != 0 {
		t.Fatal("non-zero status returned, failed to run feature tests")
	}
}
